"""JSON serialization and a standalone "Triage Console" HTML report.

The report is styled as a SOC analyst's triage console: a dense, neutral
light interface in the vein of SIEM dashboards, MISP, and TheHive. Severity
is the only color story (critical red, high amber); everything else stays
neutral so the signal never competes with decoration. Monospace type marks
machine-derived values (scores, headers data, evidence) while a system sans
carries analyst prose. Each report has one case file per message with a
verdict, an authentication trail, quoted findings, and a recommended action.
The HTML is fully self-contained (inline CSS, no external assets, no
clickable links) so it opens offline.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Iterable

from .models import EmailAnalysis


RISK_ORDER = ("critical", "high", "moderate", "low")


def build_batch_payload(analyses: Iterable[EmailAnalysis]) -> dict[str, object]:
    items = list(analyses)
    levels = Counter(item.risk_level for item in items)
    categories = Counter(finding.category for item in items for finding in item.findings)
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "emails_analyzed": len(items),
            "average_score": round(sum(item.score for item in items) / len(items), 1) if items else 0.0,
            "risk_levels": {level: levels.get(level, 0) for level in RISK_ORDER},
            "findings_by_category": dict(sorted(categories.items())),
        },
        "emails": [item.to_dict() for item in items],
    }


def write_json_report(analyses: Iterable[EmailAnalysis], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_batch_payload(analyses), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Triage console building blocks
# ---------------------------------------------------------------------------

_VERDICT_COPY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MODERATE",
    "low": "LOW",
}

_ACTION_COPY = {
    "critical": (
        "Treat this message as hostile. Do not open its links or attachments, and do not reply. "
        "Quarantine the message, then verify the supposed sender through a channel you trust, "
        "such as the official website or a known phone number."
    ),
    "high": (
        "Do not interact with this message until the sender is verified independently. "
        "Quarantine it and escalate to your security team."
    ),
    "moderate": (
        "Review before acting. Verify any unusual request through a known good channel "
        "before clicking, replying, or sending anything back."
    ),
    "low": (
        "No structural indicators were found. Nothing in this message matches the analyzer's "
        "rule set, so routine caution applies."
    ),
}

_READ_CLOSE = {
    "critical": "In short, treat this message as hostile and do not interact with it.",
    "high": "In short, do not interact with this message until the sender is verified.",
    "moderate": "In short, verify the sender through a known good channel before acting.",
}

# Rule id priority order for the analyst's plain-language read.
_READ_SENTENCES: tuple[tuple[str, str], ...] = (
    ("content.credentials", "The message asks the reader to sign in, verify identity, or hand over credentials."),
    ("url.link_text_mismatch", "The visible link text hides a different real destination."),
    ("url.lookalike_domain", "A link destination imitates a trusted domain name."),
    ("header.display_name_spoofing", "The sender name claims an identity the sending domain does not match."),
    ("url.ip_literal", "A link points at a raw IP address instead of a named domain."),
    ("url.shortener", "A shortened link hides where it really leads."),
    ("content.urgency", "The wording pressures the reader to act before checking."),
    ("header.reply_to_mismatch", "Replies would go to a domain the visible sender does not control."),
    ("content.suspicious_attachment", "An attachment can carry active or executable content."),
    ("header.suspicious_origin", "The sending infrastructure looks disposable or minimally identified."),
)


def _analyst_read(item: EmailAnalysis) -> str:
    """A short human-voice read of the case, composed from the top findings."""
    if not item.findings:
        return (
            "Nothing in the headers, links, wording, or attachments matches the analyzer's "
            "phishing rules. The message reads as ordinary correspondence."
        )
    rule_ids = {finding.rule_id for finding in item.findings}
    sentences = [text for rule_id, text in _READ_SENTENCES if rule_id in rule_ids][:3]
    if any(item.authentication.get(mech) in ("fail", "softfail") for mech in ("spf", "dkim", "dmarc")):
        sentences.append("Mail authentication fails for the claimed sender.")
    sentences = sentences[:3]
    close = _READ_CLOSE.get(item.risk_level, "")
    body = " ".join(sentences)
    return f"{body} {close}".strip()


def _auth_outcome(status: str | None) -> tuple[str, str]:
    """Map a raw auth status to (display label, css class)."""
    normalized = (status or "not present").lower()
    if normalized == "pass":
        return "PASS", "ok"
    if normalized == "fail":
        return "FAIL", "bad"
    if normalized == "softfail":
        return "SOFTFAIL", "warn"
    if normalized == "none":
        return "NONE", "warn"
    return "NOT REPORTED", "na"


def _auth_trail(authentication: dict[str, str]) -> str:
    cells = []
    for mechanism in ("spf", "dkim", "dmarc"):
        raw = authentication.get(mechanism, "not present")
        label, state = _auth_outcome(raw)
        cells.append(
            f'<div class="auth"><span class="a-name">{mechanism.upper()}</span>'
            f'<span class="a-val {state}">{label}</span>'
            f'<span class="a-raw">reported "{escape(raw)}"</span></div>'
        )
    return '<div class="authgrid">' + "".join(cells) + "</div>"


def _evidence_blocks(evidence: list[str] | tuple[str, ...]) -> str:
    if not evidence:
        return ""
    return '<div class="evs">' + "".join(f"<div class=\"ev\"><code>{escape(item)}</code></div>" for item in evidence) + "</div>"


def _finding_entry(finding, index: int) -> str:
    return (
        f'<li class="finding">'
        f'<div class="f-top"><span class="f-num">{index:02d}</span>'
        f'<div class="f-head"><h5>{escape(finding.title)}</h5>'
        f'<span class="f-meta">+{finding.weight} points · {escape(finding.category)}</span></div></div>'
        f'<p class="f-exp">{escape(finding.explanation)}</p>'
        f"{_evidence_blocks(finding.evidence)}"
        f"</li>"
    )


def _signal_table(item: EmailAnalysis) -> str:
    recipients = ", ".join(item.recipients) or "Not specified"
    rows = (
        ("From", item.sender or "Unknown"),
        ("To / Cc", recipients),
        ("Subject", item.subject or "(no subject)"),
    )
    body = "".join(f"<tr><th scope=\"row\">{label}</th><td>{escape(value)}</td></tr>" for label, value in rows)
    return f'<table class="signal"><tbody>{body}</tbody></table>'


def _exhibits(item: EmailAnalysis, compact: bool = False) -> str:
    if item.urls:
        url_items = "".join(f"<li><code>{escape(url)}</code></li>" for url in item.urls)
        urls = f'<ul class="mono-list">{url_items}</ul>'
    else:
        urls = '<p class="quiet">None.</p>'
    if item.attachments:
        att_items = "".join(f"<li><code>{escape(name)}</code></li>" for name in item.attachments)
        attachments = f'<ul class="mono-list">{att_items}</ul>'
    else:
        attachments = '<p class="quiet">None.</p>'
    warn = '<p class="warn">Shown as plain text. Do not open, visit, or download.</p>' if item.urls and not compact else ""
    return (
        f'<div class="exhibits">'
        f'<div class="exhibit"><h5>Links ({len(item.urls)})</h5>{warn}{urls}</div>'
        f'<div class="exhibit"><h5>Attachments ({len(item.attachments)})</h5>{attachments}</div>'
        f"</div>"
    )


def _verdict_block(item: EmailAnalysis) -> str:
    word = _VERDICT_COPY[item.risk_level]
    return (
        f'<div class="verdict sev-{item.risk_level}">'
        f'<div class="v-word sev-{item.risk_level}">{word}</div>'
        f'<div class="v-score"><span class="v-num">{item.score}</span><span class="v-den">/ 100</span></div>'
        f'</div><div class="meter" aria-hidden="true">'
        f'<span class="sev-{item.risk_level}" style="width:{item.score}%"></span></div>'
    )


def _action_block(item: EmailAnalysis) -> str:
    return (
        f'<div class="action sev-{item.risk_level}">'
        f'<h4 class="sec-label">Recommended action</h4>'
        f"<p>{_ACTION_COPY[item.risk_level]}</p></div>"
    )


def _case_file(item: EmailAnalysis, number: int, total: int) -> str:
    """A full case file for a flagged message."""
    anchor = f"case-{number}"
    findings = "".join(_finding_entry(finding, i + 1) for i, finding in enumerate(item.findings))
    return (
        f'<section class="case" id="{anchor}">'
        f'<div class="case-top"><span class="case-id">CASE {number:02d} / {total:02d}</span>'
        f'<span class="case-file">{escape(item.filename)}</span></div>'
        f'<div class="case-inner">'
        f'<h3 class="case-subject">{escape(item.subject or "(no subject)")}</h3>'
        f"{_verdict_block(item)}"
        f'<p class="read">{_analyst_read(item)}</p>'
        f'<h4 class="sec-label">Message signal</h4>{_signal_table(item)}'
        f'<h4 class="sec-label">Authentication trail</h4>{_auth_trail(item.authentication)}'
        f'<h4 class="sec-label">Findings ({len(item.findings)})</h4>'
        f'<ol class="findings">{findings}</ol>'
        f'<h4 class="sec-label">Exhibits</h4>{_exhibits(item)}'
        f"{_action_block(item)}"
        f"</div></section>"
    )


def _cleared_case(item: EmailAnalysis, number: int, total: int) -> str:
    """A compact case file for a message with no findings."""
    anchor = f"case-{number}"
    return (
        f'<section class="case cleared" id="{anchor}">'
        f'<div class="case-top"><span class="case-id">CASE {number:02d} / {total:02d}</span>'
        f'<span class="case-file">{escape(item.filename)}</span></div>'
        f'<div class="case-inner">'
        f'<div class="clear-row"><span class="v-word small sev-{item.risk_level}">LOW</span>'
        f'<div><h3 class="case-subject small">{escape(item.subject or "(no subject)")}</h3>'
        f'<p class="read small"><span class="riskline">Risk {item.score}/100.</span> '
        f"{_analyst_read(item)}</p></div></div>"
        f'<h4 class="sec-label">Message signal</h4>{_signal_table(item)}'
        f'<h4 class="sec-label">Authentication trail</h4>{_auth_trail(item.authentication)}'
        f"{_action_block(item)}"
        f"</div></section>"
    )


def _index_table(items: list[EmailAnalysis]) -> str:
    rows = []
    for number, item in enumerate(items, start=1):
        rows.append(
            f"<tr>"
            f'<td class="c-case"><a href="#case-{number}">{number:02d}</a></td>'
            f'<td class="c-file"><a href="#case-{number}">{escape(item.filename)}</a></td>'
            f"<td>{escape(item.subject or '(no subject)')}</td>"
            f"<td class=\"c-sender\">{escape(item.sender or 'Unknown')}</td>"
            f'<td class="c-score"><span class="sev-{item.risk_level}">{item.score}</span></td>'
            f'<td class="c-verdict"><span class="sev-{item.risk_level}">{_VERDICT_COPY[item.risk_level]}</span></td>'
            f"</tr>"
        )
    return (
        '<div class="tablewrap"><table class="index"><thead><tr>'
        "<th>Case</th><th>File</th><th>Subject</th><th>Sender</th><th>Score</th><th>Verdict</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _summary_panel(items: list[EmailAnalysis], average: float) -> str:
    counts = Counter(item.risk_level for item in items)
    stats = [
        ("Messages examined", str(len(items)), ""),
        ("Critical", str(counts.get("critical", 0)), "sev-critical"),
        ("High", str(counts.get("high", 0)), "sev-high"),
        ("Moderate", str(counts.get("moderate", 0)), ""),
        ("Low", str(counts.get("low", 0)), ""),
        ("Mean risk score", f"{average}", ""),
    ]
    cells = "".join(
        f'<div class="stat"><dt>{label}</dt><dd class="{cls}">{value}</dd></div>' for label, value, cls in stats
    )
    flagged = counts.get("critical", 0) + counts.get("high", 0)
    if flagged:
        read = (
            f"{flagged} of {len(items)} messages show strong phishing indicators. "
            "Start with the flagged cases in the index below; each one lays out the evidence "
            "behind its verdict and the action to take."
        )
    else:
        read = (
            "No message crosses the high risk threshold. The cases below document what was "
            "checked and why each message cleared."
        )
    return (
        f'<section class="summary"><div class="sum-read"><h2 class="sec-label">Executive read</h2>'
        f"<p>{read}</p></div>"
        f'<dl class="stats">{cells}</dl></section>'
    )


# Triage console skin: cool gray-blue surfaces, dense neutral cards, severity
# as the only color. System sans for prose/UI, monospace for machine values.
_CSS = """
:root{
  --bg:#f2f5f8; --card:#ffffff; --panel:#f7fafc; --cell:#fbfdff;
  --line:#dde4ea; --line-soft:#e9eef3;
  --ink:#17222e; --muted:#5d6f82; --faint:#8ba0b3;
  --slate:#1a2430; --slate-ink:#eef3f7; --slate-dim:#aebcc9;
  --red:#d92d20; --amber:#b54708;
  --red-tint:#fdeceb; --amber-tint:#fdf3e7;
  --neutral:#9db0c2;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;
  --sans:system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans)}
::selection{background:#cfdbe5}
.strip{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
  background:var(--slate);color:var(--slate-dim);padding:8px 24px;
  font:11px/1.4 var(--mono);letter-spacing:.12em;text-transform:uppercase}
.strip .up{color:var(--slate-ink)}
main{max-width:1080px;margin:0 auto;padding:32px 24px 64px}
.cover{display:flex;gap:20px;align-items:flex-start;border:1px solid var(--line);
  background:var(--card);padding:22px 26px;margin-bottom:20px}
.sigil{flex:0 0 auto;margin-top:2px}
.eyebrow{font:11px/1.4 var(--mono);letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin:0 0 8px}
h1{font:700 30px/1.15 var(--sans);margin:0 0 8px;letter-spacing:-.01em}
.lede{font-size:15px;color:var(--muted);margin:0;max-width:72ch}
.lede strong{color:var(--ink)}
.summary{display:grid;grid-template-columns:1.15fr 1fr;border:1px solid var(--line);
  background:var(--card);margin-bottom:20px}
.sum-read{padding:18px 22px;border-right:1px solid var(--line)}
.sum-read p{margin:8px 0 0;color:var(--muted);font-size:14.5px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);margin:0}
.stat{padding:12px 16px;border-bottom:1px solid var(--line-soft);border-right:1px solid var(--line-soft);margin:0}
.stat dt{font:10px/1.4 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint)}
.stat dd{margin:4px 0 0;font:700 21px/1.1 var(--mono)}
.sev-critical{color:var(--red)} .sev-high{color:var(--amber)}
.sev-moderate,.sev-low{color:var(--muted)}
.sec-label{font:600 11px/1.4 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:0}
section.block{margin-bottom:20px}
.blockhead{margin:0 0 10px}
.tablewrap{overflow-x:auto;border:1px solid var(--line);background:var(--card)}
table.index{width:100%;border-collapse:collapse;font-size:13.5px;min-width:720px}
table.index th{font:600 10.5px/1.4 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);
  text-align:left;padding:9px 14px;border-bottom:1px solid var(--line);background:var(--panel)}
table.index td{padding:8px 14px;border-bottom:1px solid var(--line-soft);vertical-align:middle}
table.index tbody tr:last-child td{border-bottom:0}
table.index tbody tr:hover{background:var(--panel)}
table.index a{color:inherit;text-decoration:none}
table.index a:hover{text-decoration:underline}
.c-case,.c-score{font-family:var(--mono);white-space:nowrap}
.c-score{font-size:15px;font-weight:700}
.c-verdict{font:700 11.5px/1.4 var(--mono);letter-spacing:.1em;white-space:nowrap}
.c-file{font-family:var(--mono);font-size:12.5px;white-space:nowrap}
.c-sender{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)}
.case{border:1px solid var(--line);background:var(--card);margin:0 0 20px;scroll-margin-top:16px}
.case-top{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
  background:var(--panel);border-bottom:1px solid var(--line);padding:9px 20px;
  font:11px/1.5 var(--mono);letter-spacing:.12em;text-transform:uppercase}
.case-id{color:var(--muted)}
.case-file{color:var(--faint);text-transform:none;letter-spacing:0}
.case-inner{padding:20px 24px 24px}
.case-subject{font:700 22px/1.25 var(--sans);margin:14px 0 12px;letter-spacing:-.01em}
.verdict{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin:0}
.v-word{font:700 15px/1 var(--sans);letter-spacing:.14em;text-transform:uppercase;
  padding:8px 12px;border:1px solid currentColor;border-radius:3px;background:var(--card)}
.v-word.small{font-size:12px;padding:6px 10px}
.v-word.sev-critical{color:var(--red);background:var(--red-tint);border-color:#f3b8b1}
.v-word.sev-high{color:var(--amber);background:var(--amber-tint);border-color:#eccfa5}
.v-word.sev-moderate,.v-word.sev-low{color:var(--muted);background:var(--panel);border-color:var(--line)}
.v-score{font-family:var(--mono);color:var(--muted);font-size:13.5px}
.v-num{font-size:28px;font-weight:700;color:var(--ink)}
.v-den{font-size:13px}
.meter{height:4px;background:var(--line-soft);border-radius:2px;margin:10px 0 18px;max-width:480px}
.meter span{display:block;height:100%;border-radius:2px}
.meter .sev-critical{background:var(--red)} .meter .sev-high{background:var(--amber)}
.meter .sev-moderate,.meter .sev-low{background:var(--neutral)}
.read{font-size:15px;line-height:1.6;max-width:76ch;margin:0 0 20px}
.read.small{font-size:14px;margin:6px 0 0;color:var(--muted)}
.riskline{font-family:var(--mono);color:var(--ink);font-size:13px}
.case .sec-label{margin:22px 0 10px;padding-top:16px;border-top:1px solid var(--line-soft)}
table.signal{width:100%;border-collapse:collapse;font-size:14px}
table.signal th{font:600 10.5px/1.4 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint);
  text-align:left;width:110px;padding:7px 14px 7px 0;vertical-align:top}
table.signal td{padding:7px 0;vertical-align:top;overflow-wrap:anywhere}
.authgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.auth{border:1px solid var(--line);background:var(--cell);border-radius:3px;padding:10px 14px}
.a-name{display:block;font:600 10.5px/1.4 var(--mono);letter-spacing:.14em;color:var(--faint)}
.a-val{display:block;font:700 17px/1.3 var(--mono);letter-spacing:.05em;margin:4px 0 2px}
.a-val.ok{color:var(--muted)} .a-val.bad{color:var(--red)} .a-val.warn{color:var(--amber)} .a-val.na{color:var(--faint)}
.a-raw{display:block;font:11.5px/1.5 var(--mono);color:var(--faint)}
ol.findings{list-style:none;margin:0;padding:0}
.finding{border:1px solid var(--line);background:var(--cell);border-radius:3px;padding:14px 16px;margin:0 0 10px}
.f-top{display:flex;gap:12px;align-items:baseline;margin-bottom:6px}
.f-num{font:700 12px/1 var(--mono);color:var(--muted);border:1px solid var(--line);border-radius:3px;
  padding:5px 7px;background:var(--card)}
.f-head h5{margin:0;font-size:15px;font-weight:650}
.f-meta{display:block;font:11.5px/1.5 var(--mono);color:var(--faint);margin-top:2px}
.f-exp{margin:0;color:var(--muted);font-size:14px;max-width:78ch}
.evs{margin-top:8px}
.ev{border-left:2px solid var(--line);background:var(--card);padding:5px 0 5px 12px;margin:5px 0}
.ev code{font:12.5px/1.55 var(--mono);color:var(--ink);overflow-wrap:anywhere}
.exhibits{display:grid;grid-template-columns:1.5fr 1fr;gap:10px}
.exhibit{border:1px solid var(--line);background:var(--cell);border-radius:3px;padding:14px 16px}
.exhibit h5{margin:0 0 6px;font:600 11px/1.4 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.warn{font:12px/1.5 var(--mono);color:var(--amber);margin:0 0 8px}
.mono-list{list-style:none;margin:0;padding:0}
.mono-list li{padding:5px 0;border-top:1px solid var(--line-soft);font-size:12.5px}
.mono-list li:first-child{border-top:0}
.mono-list code{font-family:var(--mono);overflow-wrap:anywhere;color:var(--ink)}
.quiet{color:var(--faint);font-size:13.5px;margin:0}
.action{border:1px solid var(--line);border-left:4px solid var(--neutral);background:var(--cell);
  border-radius:3px;padding:14px 18px;margin-top:20px}
.action.sev-critical{border-left-color:var(--red);background:var(--red-tint)}
.action.sev-high{border-left-color:var(--amber);background:var(--amber-tint)}
.action .sec-label{margin:0 0 6px;padding:0;border:0}
.action p{margin:0;font-size:14.5px;max-width:78ch}
.clear-row{display:flex;gap:14px;align-items:flex-start;margin:14px 0 4px}
.case-subject.small{font-size:19px;margin:0 0 4px}
footer.method{border:1px solid var(--line);background:var(--card);margin-top:32px;
  padding:22px 26px;color:var(--muted);font-size:14px}
footer.method h2{margin-bottom:10px}
.bands{width:100%;border-collapse:collapse;margin:10px 0 18px;font-size:13.5px}
.bands th{font:600 10.5px/1.4 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--faint);
  text-align:left;padding:7px 12px 7px 0;border-bottom:1px solid var(--line)}
.bands td{padding:7px 12px 7px 0;border-bottom:1px solid var(--line-soft);vertical-align:top}
.bands td:first-child{font-family:var(--mono);white-space:nowrap}
footer.method p{max-width:82ch}
.colophon{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:20px;
  padding-top:14px;border-top:1px solid var(--line-soft);font:11.5px/1.6 var(--mono);color:var(--faint)}
@media(max-width:820px){
  main{padding:24px 14px 48px}
  .cover{flex-direction:column;gap:12px}
  .summary{grid-template-columns:1fr}
  .sum-read{border-right:0;border-bottom:1px solid var(--line)}
  .stats{grid-template-columns:repeat(2,1fr)}
  .authgrid{grid-template-columns:1fr}
  .exhibits{grid-template-columns:1fr}
  .case-inner{padding:16px 16px 20px}
  table.signal th{width:88px}
}
@media print{
  body{background:#fff}
  .strip{background:#fff;color:#000;border-bottom:1px solid #000}
  .case,.summary,.auth,.finding,.exhibit,.action,.tablewrap,footer.method{break-inside:avoid;background:#fff}
  .sev-critical,.a-val.bad,.v-word.sev-critical{color:#b00020}
  .sev-high,.a-val.warn,.warn,.v-word.sev-high{color:#8a5a00}
}
"""

_SIGIL = (
    '<svg viewBox="0 0 40 40" width="34" height="34" aria-hidden="true">'
    '<rect x="2" y="2" width="36" height="36" rx="7" fill="#1a2430"/>'
    '<path d="M12 15.5l7 6-7 6" fill="none" stroke="#f2f5f8" stroke-width="2.6" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    '<line x1="20.5" y1="28.5" x2="30" y2="28.5" stroke="#f2f5f8" stroke-width="2.6" '
    'stroke-linecap="round"/></svg>'
)


def render_html_report(analyses: Iterable[EmailAnalysis], generated_at: str | None = None) -> str:
    items = sorted(list(analyses), key=lambda value: (-value.score, value.filename.lower()))
    generated = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(item.risk_level for item in items)
    average = round(sum(item.score for item in items) / len(items), 1) if items else 0.0
    flagged = counts.get("critical", 0) + counts.get("high", 0)

    if items:
        lede = (
            f"<strong>{len(items)}</strong> messages examined. "
            f"<strong>{flagged}</strong> flagged critical or high. "
            "Each case below carries its verdict, the evidence behind it, and the action to take."
        )
    else:
        lede = "No messages were examined. Run the analyzer against a directory of .eml files to produce a report."

    case_sections = []
    for number, item in enumerate(items, start=1):
        if item.findings:
            case_sections.append(_case_file(item, number, len(items)))
        else:
            case_sections.append(_cleared_case(item, number, len(items)))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Triage Console: Email Analysis Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="strip"><span><span class="up">Triage console</span> // Static analysis</span><span>Offline &middot; No network contact &middot; {escape(generated)}</span></div>
<main>
<header class="cover">
<div class="sigil">{_SIGIL}</div>
<div>
<p class="eyebrow">Phishing email analysis &middot; SOC triage console</p>
<h1>Phishing Triage Console</h1>
<p class="lede">{lede}</p>
</div>
</header>
{_summary_panel(items, average) if items else ""}
<section class="block" aria-label="Case index">
<h2 class="sec-label blockhead">Case index</h2>
{_index_table(items) if items else '<p class="quiet">No emails were analyzed.</p>'}
</section>
{''.join(case_sections)}
<footer class="method">
<h2 class="sec-label">How to read this report</h2>
<table class="bands">
<thead><tr><th>Score</th><th>Band</th><th>Reading</th></tr></thead>
<tbody>
<tr><td>75&ndash;100</td><td>Critical</td><td>Strongly consistent with phishing behavior.</td></tr>
<tr><td>50&ndash;74</td><td>High</td><td>Multiple strong indicators; avoid interacting until verified.</td></tr>
<tr><td>20&ndash;49</td><td>Moderate</td><td>Review the message and verify unusual requests independently.</td></tr>
<tr><td>0&ndash;19</td><td>Low</td><td>No or few configured structural indicators.</td></tr>
</tbody>
</table>
<p>Every finding adds a documented weight to the message score, capped at 100. A low score is not proof that a message is safe, and a high score is not a legal or forensic verdict. Authentication results are read from the message as supplied; this tool does not independently validate cryptographic signatures.</p>
<p>This report is a triage aid. It performs no network requests, reputation lookups, attachment execution, or URL visits. Review important messages with trusted security controls and independent sender verification.</p>
<div class="colophon"><span>Generated {escape(generated)} &middot; phishing-email-analyzer (stdlib only)</span><span>End of report</span></div>
</footer>
</main>
</body>
</html>"""


def write_html_report(analyses: Iterable[EmailAnalysis], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(analyses), encoding="utf-8")
    return path
