"""Message parsing, rule orchestration, and weighted scoring."""

from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from .content_rules import attachment_names, run_content_rules
from .header_rules import parse_authentication_results, run_header_rules
from .models import EmailAnalysis, Finding
from .url_rules import extract_links, run_url_rules


RISK_THRESHOLDS = (
    (75, "critical"),
    (50, "high"),
    (20, "moderate"),
    (0, "low"),
)


def score_findings(findings: list[Finding]) -> int:
    """Sum rule weights and cap the human-facing score at 100."""

    return min(100, sum(max(0, finding.weight) for finding in findings))


def risk_level(score: int) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def analyze_email(message: Message, filename: str = "message.eml") -> EmailAnalysis:
    """Apply all configured rules to one already-parsed message."""

    links = extract_links(message)
    findings = run_header_rules(message) + run_url_rules(links) + run_content_rules(message)
    findings.sort(key=lambda finding: (-finding.weight, finding.rule_id))
    score = score_findings(findings)
    recipient_values = message.get_all("To", []) + message.get_all("Cc", [])
    recipients = [address for _, address in getaddresses(recipient_values) if address]
    sender_name, sender_address = parseaddr(message.get("From", ""))
    sender = f"{sender_name} <{sender_address}>" if sender_name and sender_address else sender_address or str(message.get("From", ""))
    return EmailAnalysis(
        filename=filename,
        subject=str(message.get("Subject", "(no subject)")),
        sender=sender,
        recipients=recipients,
        score=score,
        risk_level=risk_level(score),
        findings=findings,
        authentication=parse_authentication_results(message),
        urls=list(dict.fromkeys(link.url for link in links)),
        attachments=attachment_names(message),
    )


def analyze_file(path: str | Path) -> EmailAnalysis:
    email_path = Path(path)
    with email_path.open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)
    return analyze_email(message, filename=email_path.name)


def discover_eml_files(path: str | Path, recursive: bool = False) -> list[Path]:
    source = Path(path)
    if source.is_file():
        return [source]
    if not source.is_dir():
        raise FileNotFoundError(f"Input path does not exist: {source}")
    pattern = "**/*.eml" if recursive else "*.eml"
    return sorted((item for item in source.glob(pattern) if item.is_file()), key=lambda item: str(item).lower())


def analyze_path(path: str | Path, recursive: bool = False) -> list[EmailAnalysis]:
    files = discover_eml_files(path, recursive=recursive)
    if not files:
        raise ValueError(f"No .eml files found in {Path(path)}")
    return [analyze_file(item) for item in files]
