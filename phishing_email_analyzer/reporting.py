"""JSON serialization and a standalone dark HTML report."""

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


def _auth_badges(authentication: dict[str, str]) -> str:
    badges: list[str] = []
    for mechanism in ("spf", "dkim", "dmarc"):
        status = authentication.get(mechanism, "not present")
        state = "pass" if status == "pass" else "unknown" if status == "not present" else "fail"
        badges.append(f'<span class="auth {state}">{mechanism.upper()}: {escape(status)}</span>')
    return "".join(badges)


def _evidence(items: list[str] | tuple[str, ...]) -> str:
    if not items:
        return ""
    return '<ul class="evidence">' + "".join(f"<li><code>{escape(item)}</code></li>" for item in items) + "</ul>"


def _message_card(item: EmailAnalysis) -> str:
    finding_rows = ""
    for finding in item.findings:
        finding_rows += (
            "<tr>"
            f'<td><span class="weight">+{finding.weight}</span></td>'
            f"<td><strong>{escape(finding.title)}</strong><span class=\"category\">{escape(finding.category)}</span></td>"
            f"<td>{escape(finding.explanation)}{_evidence(finding.evidence)}</td>"
            "</tr>"
        )
    if not finding_rows:
        finding_rows = '<tr><td colspan="3" class="empty">No configured phishing indicators were detected.</td></tr>'

    url_list = _evidence(item.urls) if item.urls else '<p class="muted">No HTTP(S) links found.</p>'
    attachment_list = _evidence(item.attachments) if item.attachments else '<p class="muted">No named attachments.</p>'
    recipients = ", ".join(item.recipients) or "Not specified"
    open_attr = " open" if item.risk_level in {"critical", "high"} else ""
    return f"""
    <details class="message-card risk-{item.risk_level}"{open_attr}>
      <summary>
        <span class="score">{item.score}</span>
        <span class="summary-main"><strong>{escape(item.filename)}</strong><span>{escape(item.subject)}</span></span>
        <span class="risk-pill">{escape(item.risk_level)}</span>
      </summary>
      <div class="message-body">
        <div class="metadata">
          <div><span>From</span><strong>{escape(item.sender or "Unknown")}</strong></div>
          <div><span>To / Cc</span><strong>{escape(recipients)}</strong></div>
          <div><span>Authentication</span><strong>{_auth_badges(item.authentication)}</strong></div>
        </div>
        <h3>Why this score</h3>
        <table><thead><tr><th>Points</th><th>Indicator</th><th>Plain-language explanation</th></tr></thead><tbody>{finding_rows}</tbody></table>
        <div class="artifacts"><section><h3>URLs ({len(item.urls)})</h3>{url_list}</section><section><h3>Attachments ({len(item.attachments)})</h3>{attachment_list}</section></div>
      </div>
    </details>"""


def render_html_report(analyses: Iterable[EmailAnalysis], generated_at: str | None = None) -> str:
    items = list(analyses)
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    counts = Counter(item.risk_level for item in items)
    average = round(sum(item.score for item in items) / len(items), 1) if items else 0.0
    cards = "".join(_message_card(item) for item in sorted(items, key=lambda value: (-value.score, value.filename.lower())))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Email Analysis Report</title>
<style>
:root{{--bg:#090d16;--panel:#111827;--panel2:#172033;--line:#29344a;--text:#e7edf7;--muted:#98a7bd;--critical:#fb7185;--high:#fb923c;--moderate:#facc15;--low:#34d399;--accent:#60a5fa}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at top right,#15213a 0,#090d16 35%);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}main{{max-width:1180px;margin:auto;padding:48px 24px 72px}}header{{margin-bottom:28px}}.eyebrow{{color:var(--accent);font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:12px}}h1{{font-size:clamp(30px,5vw,48px);line-height:1.05;margin:8px 0 12px}}h2,h3{{margin:0}}header p,.muted{{color:var(--muted)}}.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:28px 0}}.stat{{background:rgba(17,24,39,.88);border:1px solid var(--line);border-radius:14px;padding:17px}}.stat strong{{display:block;font-size:27px}}.stat span{{color:var(--muted);font-size:13px}}.stat.critical strong{{color:var(--critical)}}.stat.high strong{{color:var(--high)}}.stat.moderate strong{{color:var(--moderate)}}.stat.low strong{{color:var(--low)}}.message-card{{background:rgba(17,24,39,.94);border:1px solid var(--line);border-left:5px solid var(--low);border-radius:14px;margin:14px 0;overflow:hidden}}.message-card.risk-critical{{border-left-color:var(--critical)}}.message-card.risk-high{{border-left-color:var(--high)}}.message-card.risk-moderate{{border-left-color:var(--moderate)}}summary{{display:flex;align-items:center;gap:16px;cursor:pointer;padding:18px 20px;list-style:none}}summary::-webkit-details-marker{{display:none}}.score{{display:grid;place-items:center;flex:0 0 48px;height:48px;border-radius:50%;background:var(--panel2);font-size:20px;font-weight:800}}.summary-main{{display:flex;flex:1;min-width:0;flex-direction:column}}.summary-main span{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted)}}.risk-pill{{text-transform:uppercase;letter-spacing:.08em;font-size:11px;font-weight:800;border:1px solid currentColor;border-radius:999px;padding:5px 9px}}.risk-critical .risk-pill{{color:var(--critical)}}.risk-high .risk-pill{{color:var(--high)}}.risk-moderate .risk-pill{{color:var(--moderate)}}.risk-low .risk-pill{{color:var(--low)}}.message-body{{border-top:1px solid var(--line);padding:20px}}.metadata{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px}}.metadata>div{{background:var(--panel2);padding:13px;border-radius:10px;overflow-wrap:anywhere}}.metadata span{{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}.metadata strong span.auth{{display:inline-block;margin:4px 5px 0 0;padding:3px 6px;border-radius:5px;background:#29344a;color:var(--text);font-size:10px}}.metadata .auth.pass{{background:#064e3b;color:#a7f3d0}}.metadata .auth.fail{{background:#4c1721;color:#fecdd3}}table{{width:100%;border-collapse:collapse;margin:10px 0 24px}}th,td{{padding:12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:var(--muted);font-size:12px;text-transform:uppercase}}th:first-child,td:first-child{{width:72px}}.weight{{color:var(--critical);font-weight:800}}.category{{display:block;color:var(--muted);font-size:12px}}.evidence{{margin:7px 0 0;padding-left:20px}}code{{color:#bfdbfe;overflow-wrap:anywhere}}.artifacts{{display:grid;grid-template-columns:2fr 1fr;gap:16px}}.artifacts section{{background:var(--panel2);padding:16px;border-radius:10px}}.empty{{color:var(--low);text-align:center;padding:24px}}footer{{color:var(--muted);font-size:13px;margin-top:32px;padding-top:18px;border-top:1px solid var(--line)}}
@media(max-width:800px){{.stats{{grid-template-columns:repeat(2,1fr)}}.metadata,.artifacts{{grid-template-columns:1fr}}table,thead,tbody,tr,th,td{{display:block}}thead{{display:none}}td:first-child{{width:auto;padding-bottom:0;border:0}}}}
</style>
</head>
<body><main>
<header><div class="eyebrow">Offline static analysis</div><h1>Phishing email analysis</h1><p>Weighted structural indicators from message headers, links, body text, and attachment names. Generated {escape(generated)}.</p></header>
<section class="stats" aria-label="Batch summary">
<div class="stat"><strong>{len(items)}</strong><span>Emails analyzed</span></div><div class="stat critical"><strong>{counts['critical']}</strong><span>Critical risk</span></div><div class="stat high"><strong>{counts['high']}</strong><span>High risk</span></div><div class="stat moderate"><strong>{counts['moderate']}</strong><span>Moderate risk</span></div><div class="stat low"><strong>{counts['low']}</strong><span>Low risk · average {average}</span></div>
</section>
<section aria-label="Email results">{cards or '<p class="empty">No emails were analyzed.</p>'}</section>
<footer>This report is a triage aid, not a verdict. It performs no network requests, reputation lookups, attachment execution, or URL visits. Review important messages with trusted security controls and independent sender verification.</footer>
</main></body></html>"""


def write_html_report(analyses: Iterable[EmailAnalysis], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(analyses), encoding="utf-8")
    return path
