from phishing_email_analyzer.header_rules import (
    check_authentication,
    check_display_name_spoofing,
    check_reply_to_mismatch,
    check_suspicious_origin,
    parse_authentication_results,
)

from .helpers import make_message


def test_parse_all_authentication_results():
    message = make_message()
    message["Authentication-Results"] = "mx.example; spf=pass; dkim=fail; dmarc=softfail"
    assert parse_authentication_results(message) == {"spf": "pass", "dkim": "fail", "dmarc": "softfail"}


def test_received_spf_fallback():
    message = make_message()
    message["Received-SPF"] = "softfail (mx.example: transitioning domain)"
    assert parse_authentication_results(message)["spf"] == "softfail"


def test_spf_failure_creates_weighted_finding():
    message = make_message()
    message["Authentication-Results"] = "mx.example; spf=fail"
    finding = check_authentication(message)[0]
    assert finding.rule_id == "header.auth.spf.fail"
    assert finding.weight == 18


def test_dkim_failure_is_flagged():
    message = make_message()
    message["Authentication-Results"] = "mx.example; dkim=fail"
    assert [item.rule_id for item in check_authentication(message)] == ["header.auth.dkim.fail"]


def test_dmarc_failure_has_strongest_auth_weight():
    message = make_message()
    message["Authentication-Results"] = "mx.example; dmarc=fail"
    assert check_authentication(message)[0].weight == 22


def test_authentication_passes_do_not_add_findings():
    message = make_message()
    message["Authentication-Results"] = "mx.example; spf=pass; dkim=pass; dmarc=pass"
    assert check_authentication(message) == []


def test_reply_to_different_domain_is_flagged():
    message = make_message(sender="Sender <sender@example.org>")
    message["Reply-To"] = "reply@unrelated.test"
    assert check_reply_to_mismatch(message)[0].rule_id == "header.reply_to_mismatch"


def test_reply_to_subdomain_of_same_organization_is_allowed():
    message = make_message(sender="Sender <sender@mail.example.org>")
    message["Reply-To"] = "reply@support.example.org"
    assert check_reply_to_mismatch(message) == []


def test_email_address_in_display_name_is_checked():
    message = make_message(sender='"trusted@example.org" <sender@unrelated.test>')
    assert check_display_name_spoofing(message)[0].rule_id == "header.display_name_spoofing"


def test_protected_brand_display_name_is_flagged():
    message = make_message(sender="PayPal Security <sender@paypa1.test>")
    assert check_display_name_spoofing(message)[0].weight == 18


def test_brand_on_expected_domain_is_allowed():
    message = make_message(sender="GitHub Notifications <noreply@github.com>")
    assert check_display_name_spoofing(message) == []


def test_suspicious_sender_tld_is_flagged():
    message = make_message(sender="Sender <sender@billing-alert.top>")
    finding = check_suspicious_origin(message)[0]
    assert finding.weight == 10
    assert ".top" in finding.evidence[0]


def test_ip_only_origin_is_flagged():
    message = make_message()
    message["Received"] = "from [198.51.100.10] by mx.example with ESMTP"
    finding = check_suspicious_origin(message)[0]
    assert finding.weight == 7
    assert "198.51.100.10" in finding.evidence[0]


def test_named_origin_is_not_flagged():
    message = make_message()
    message["Received"] = "from mail.example.org (mail.example.org [192.0.2.10]) by mx.example"
    assert check_suspicious_origin(message) == []
