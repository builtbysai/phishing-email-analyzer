"""Pure rules for sender identity and authentication headers."""

from __future__ import annotations

import ipaddress
import re
from email.message import Message
from email.utils import parseaddr

from .common import organizational_domain
from .models import Finding


BRAND_DOMAINS = {
    "amazon": "amazon.com",
    "apple": "apple.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "okta": "okta.com",
    "paypal": "paypal.com",
}

SUSPICIOUS_TLDS = {
    "click",
    "country",
    "download",
    "gq",
    "link",
    "mov",
    "rest",
    "tk",
    "top",
    "work",
    "xyz",
    "zip",
}

AUTH_WEIGHTS = {
    "spf": {"fail": 18, "softfail": 10, "neutral": 4, "none": 4, "temperror": 6, "permerror": 8},
    "dkim": {"fail": 16, "neutral": 4, "none": 4, "temperror": 6, "permerror": 8},
    "dmarc": {"fail": 22, "bestguesspass": 3, "none": 4, "temperror": 6, "permerror": 8},
}


def address_domain(value: str) -> str:
    address = parseaddr(value)[1]
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().rstrip(".")


def parse_authentication_results(message: Message) -> dict[str, str]:
    """Extract SPF, DKIM and DMARC outcomes when an email supplies them."""

    combined = "\n".join(message.get_all("Authentication-Results", []))
    statuses: dict[str, str] = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"(?:^|[;\s]){mechanism}\s*=\s*([a-zA-Z]+)", combined, re.I)
        if match:
            statuses[mechanism] = match.group(1).lower()
    if "spf" not in statuses:
        received_spf = " ".join(message.get_all("Received-SPF", []))
        match = re.search(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", received_spf, re.I)
        if match:
            statuses["spf"] = match.group(1).lower()
    return statuses


def check_authentication(message: Message) -> list[Finding]:
    findings: list[Finding] = []
    for mechanism, status in parse_authentication_results(message).items():
        weight = AUTH_WEIGHTS.get(mechanism, {}).get(status, 0)
        if not weight:
            continue
        upper = mechanism.upper()
        findings.append(
            Finding(
                rule_id=f"header.auth.{mechanism}.{status}",
                category="Headers",
                title=f"{upper} reported {status}",
                explanation=f"The message's authentication header reports {upper}={status}; this weakens confidence that the sender is authorized.",
                weight=weight,
                evidence=(f"{upper}={status}",),
            )
        )
    return findings


def check_reply_to_mismatch(message: Message) -> list[Finding]:
    from_domain = address_domain(message.get("From", ""))
    reply_domain = address_domain(message.get("Reply-To", ""))
    if not from_domain or not reply_domain:
        return []
    if organizational_domain(from_domain) == organizational_domain(reply_domain):
        return []
    return [
        Finding(
            rule_id="header.reply_to_mismatch",
            category="Headers",
            title="Reply-To points to a different domain",
            explanation="Replies would go to a domain unrelated to the visible From address, a common sender-impersonation technique.",
            weight=12,
            evidence=(f"From: {from_domain}", f"Reply-To: {reply_domain}"),
        )
    ]


def check_display_name_spoofing(message: Message) -> list[Finding]:
    raw_from = message.get("From", "")
    display_name, address = parseaddr(raw_from)
    sender_domain = address_domain(address)
    if not display_name or not sender_domain:
        return []

    evidence: list[str] = []
    embedded_addresses = re.findall(r"[\w.+-]+@([\w.-]+)", display_name, re.I)
    if any(organizational_domain(domain) != organizational_domain(sender_domain) for domain in embedded_addresses):
        evidence.append(f'Display name: "{display_name}"')

    lowered = display_name.lower()
    for brand, expected_domain in BRAND_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", lowered) and organizational_domain(sender_domain) != expected_domain:
            evidence.append(f"Claims {brand.title()} but uses {sender_domain}")
            break

    if not evidence:
        return []
    return [
        Finding(
            rule_id="header.display_name_spoofing",
            category="Headers",
            title="Display name may impersonate another sender",
            explanation="The friendly sender name claims an identity that does not match the actual address domain.",
            weight=18,
            evidence=tuple(evidence),
        )
    ]


def _origin_from_clause(received_value: str) -> str:
    match = re.search(r"\bfrom\s+([^\s;(]+|\[[^]]+\])", received_value, re.I)
    return match.group(1).strip("[]") if match else ""


def check_suspicious_origin(message: Message) -> list[Finding]:
    evidence: list[str] = []
    sender_domain = address_domain(message.get("From", ""))
    if sender_domain and sender_domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        evidence.append(f"Sender domain uses .{sender_domain.rsplit('.', 1)[-1]}")

    received = message.get_all("Received", [])
    if received:
        origin = _origin_from_clause(received[-1])
        try:
            ipaddress.ip_address(origin)
        except ValueError:
            pass
        else:
            evidence.append(f"Earliest Received hop identifies only an IP: {origin}")

    if not evidence:
        return []
    weight = 10 if any(item.startswith("Sender domain") for item in evidence) else 7
    return [
        Finding(
            rule_id="header.suspicious_origin",
            category="Headers",
            title="Origin has suspicious structural traits",
            explanation="The sender domain or earliest mail hop uses traits often seen in disposable or minimally identified sending infrastructure.",
            weight=weight,
            evidence=tuple(evidence),
        )
    ]


HEADER_RULES = (
    check_authentication,
    check_reply_to_mismatch,
    check_display_name_spoofing,
    check_suspicious_origin,
)


def run_header_rules(message: Message) -> list[Finding]:
    return [finding for rule in HEADER_RULES for finding in rule(message)]
