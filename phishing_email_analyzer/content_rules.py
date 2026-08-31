"""Pure body-language and attachment-name heuristics."""

from __future__ import annotations

import re
from email.message import Message

from .common import message_body_text
from .models import Finding


URGENCY_PATTERNS = (
    r"\bact (?:now|immediately)\b",
    r"\bimmediate action (?:is )?required\b",
    r"\bwithin (?:the next )?\d+ (?:minutes?|hours?)\b",
    r"\b(?:account|access) (?:will be|has been) (?:closed|disabled|locked|suspended)\b",
    r"\bfinal (?:warning|notice)\b",
    r"\bexpires? (?:today|immediately|soon)\b",
    r"\burgent(?:ly)?\b",
)

CREDENTIAL_PATTERNS = (
    r"\bverify (?:your )?(?:account|identity|password)\b",
    r"\bconfirm (?:your )?(?:account|identity|credentials)\b",
    r"\b(?:log|sign) ?in (?:to|with|using)\b",
    r"\benter (?:your )?(?:password|credentials|security code|one-time code)\b",
    r"\breset (?:your )?password\b",
    r"\bmulti-factor authentication\b",
    r"\bMFA code\b",
)

EXECUTABLE_EXTENSIONS = {".bat", ".cmd", ".com", ".exe", ".hta", ".jar", ".jse", ".lnk", ".msi", ".pif", ".ps1", ".scr", ".vbe", ".vbs"}
MACRO_ARCHIVE_EXTENSIONS = {".7z", ".docm", ".img", ".iso", ".pptm", ".rar", ".xlsm", ".zip"}
WEB_EXTENSIONS = {".htm", ".html", ".svg"}


def attachment_names(message: Message) -> list[str]:
    names: list[str] = []
    for part in message.walk():
        filename = part.get_filename()
        if filename:
            names.append(str(filename))
    return names


def check_urgency(text: str) -> list[Finding]:
    matches = [match.group(0) for pattern in URGENCY_PATTERNS if (match := re.search(pattern, text, re.I))]
    if not matches:
        return []
    return [
        Finding(
            rule_id="content.urgency",
            category="Content",
            title="Message uses pressure or urgency language",
            explanation="Time pressure can push a recipient to act before independently checking the request.",
            weight=10,
            evidence=tuple(matches[:5]),
        )
    ]


def check_credential_language(text: str) -> list[Finding]:
    matches = [match.group(0) for pattern in CREDENTIAL_PATTERNS if (match := re.search(pattern, text, re.I))]
    if not matches:
        return []
    return [
        Finding(
            rule_id="content.credentials",
            category="Content",
            title="Message asks for authentication information",
            explanation="The wording directs the reader toward a sign-in, identity check, password, or security-code action commonly used in credential harvesting.",
            weight=14,
            evidence=tuple(matches[:5]),
        )
    ]


def check_suspicious_attachments(names: list[str]) -> list[Finding]:
    executable: list[str] = []
    macro_or_archive: list[str] = []
    web_files: list[str] = []
    double_extensions: list[str] = []
    for name in names:
        lowered = name.lower().strip()
        suffix = "." + lowered.rsplit(".", 1)[-1] if "." in lowered else ""
        if suffix in EXECUTABLE_EXTENSIONS:
            executable.append(name)
            if re.search(r"\.(?:pdf|docx?|xlsx?|jpg|png)" + re.escape(suffix) + r"$", lowered):
                double_extensions.append(name)
        elif suffix in MACRO_ARCHIVE_EXTENSIONS:
            macro_or_archive.append(name)
        elif suffix in WEB_EXTENSIONS:
            web_files.append(name)

    evidence = double_extensions + executable + macro_or_archive + web_files
    if not evidence:
        return []
    if executable:
        weight = 25
        description = "an executable or script attachment"
    elif macro_or_archive:
        weight = 15
        description = "a macro-enabled document, disk image, or archive attachment"
    else:
        weight = 12
        description = "an active web-content attachment"
    return [
        Finding(
            rule_id="content.suspicious_attachment",
            category="Content",
            title="Attachment type can carry active content",
            explanation=f"The message includes {description}; unexpected files of this type should be verified before opening.",
            weight=weight,
            evidence=tuple(dict.fromkeys(evidence)),
        )
    ]


CONTENT_RULES = (check_urgency, check_credential_language)


def run_content_rules(message: Message) -> list[Finding]:
    text = message_body_text(message)
    findings = [finding for rule in CONTENT_RULES for finding in rule(text)]
    findings.extend(check_suspicious_attachments(attachment_names(message)))
    return findings
