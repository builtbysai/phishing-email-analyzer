"""Small serializable data models used by every analyzer component."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    """One rule match and its contribution to the risk score."""

    rule_id: str
    category: str
    title: str
    explanation: str
    weight: int
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence"] = list(self.evidence)
        return data


@dataclass
class EmailAnalysis:
    """Complete analysis for a single message."""

    filename: str
    subject: str
    sender: str
    recipients: list[str]
    score: int
    risk_level: str
    findings: list[Finding] = field(default_factory=list)
    authentication: dict[str, str] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "subject": self.subject,
            "sender": self.sender,
            "recipients": self.recipients,
            "score": self.score,
            "risk_level": self.risk_level,
            "authentication": self.authentication,
            "urls": self.urls,
            "attachments": self.attachments,
            "findings": [finding.to_dict() for finding in self.findings],
        }
