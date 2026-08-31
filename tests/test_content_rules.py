from phishing_email_analyzer.content_rules import (
    attachment_names,
    check_credential_language,
    check_suspicious_attachments,
    check_urgency,
)

from .helpers import make_message


def test_urgency_language_is_flagged():
    finding = check_urgency("Immediate action is required. Act now.")[0]
    assert finding.rule_id == "content.urgency"
    assert finding.weight == 10


def test_routine_language_is_not_urgent():
    assert check_urgency("The monthly notes are available for review.") == []


def test_credential_harvesting_language_is_flagged():
    finding = check_credential_language("Sign in to verify your account and enter your password.")[0]
    assert finding.rule_id == "content.credentials"
    assert finding.weight == 14


def test_unrelated_content_has_no_credential_finding():
    assert check_credential_language("Lunch begins at noon in the main room.") == []


def test_executable_attachment_has_high_weight():
    finding = check_suspicious_attachments(["review.exe"])[0]
    assert finding.weight == 25


def test_macro_enabled_attachment_is_flagged():
    finding = check_suspicious_attachments(["invoice.xlsm"])[0]
    assert finding.weight == 15


def test_html_attachment_is_flagged():
    finding = check_suspicious_attachments(["secure-message.html"])[0]
    assert finding.weight == 12


def test_safe_pdf_attachment_is_allowed():
    assert check_suspicious_attachments(["guide.pdf"]) == []


def test_double_extension_is_preserved_as_evidence():
    finding = check_suspicious_attachments(["statement.pdf.exe"])[0]
    assert finding.evidence[0] == "statement.pdf.exe"


def test_attachment_names_are_extracted():
    message = make_message()
    message.add_attachment(b"synthetic", maintype="application", subtype="pdf", filename="guide.pdf")
    assert attachment_names(message) == ["guide.pdf"]
