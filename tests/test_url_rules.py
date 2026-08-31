from phishing_email_analyzer.url_rules import (
    Link,
    check_ip_literal_urls,
    check_link_text_mismatch,
    check_lookalike_domains,
    check_url_shorteners,
    extract_links,
    looks_like_protected_domain,
)

from .helpers import make_message


def test_extract_plain_text_url():
    message = make_message(body="Read https://docs.example.org/guide for details.")
    assert [link.url for link in extract_links(message)] == ["https://docs.example.org/guide"]


def test_extract_html_href_and_visible_text():
    message = make_message(body='<p><a href="https://target.example/path">Visible portal</a></p>', subtype="html")
    link = extract_links(message)[0]
    assert link.url == "https://target.example/path"
    assert link.text == "Visible portal"


def test_html_link_text_mismatch_is_flagged():
    links = [Link("https://evil.example/login", "https://accounts.google.com/login", "html")]
    finding = check_link_text_mismatch(links)[0]
    assert finding.rule_id == "url.link_text_mismatch"
    assert "google.com" in finding.evidence[0]


def test_matching_link_text_is_allowed():
    links = [Link("https://login.example.org/path", "https://www.example.org/home", "html")]
    assert check_link_text_mismatch(links) == []


def test_shortener_is_flagged():
    finding = check_url_shorteners([Link("https://bit.ly/synthetic")])[0]
    assert finding.rule_id == "url.shortener"
    assert finding.weight == 12


def test_normal_domain_is_not_shortener():
    assert check_url_shorteners([Link("https://links.example.org/synthetic")]) == []


def test_leetspeak_domain_matches_protected_domain():
    assert looks_like_protected_domain("paypa1.com") == "paypal.com"


def test_exact_protected_domain_is_not_lookalike():
    assert looks_like_protected_domain("www.microsoft.com") == ""


def test_lookalike_url_is_flagged():
    finding = check_lookalike_domains([Link("https://paypa1.com/login")])[0]
    assert finding.rule_id == "url.lookalike_domain"


def test_punycode_url_is_flagged():
    finding = check_lookalike_domains([Link("https://xn--pple-43d.example/login")])[0]
    assert "xn--" in finding.evidence[0]


def test_ipv4_literal_url_is_flagged():
    finding = check_ip_literal_urls([Link("http://198.51.100.42/login")])[0]
    assert finding.evidence == ("198.51.100.42",)


def test_ipv6_literal_url_is_flagged():
    finding = check_ip_literal_urls([Link("https://[2001:db8::10]/login")])[0]
    assert finding.evidence == ("2001:db8::10",)


def test_named_url_is_not_ip_literal():
    assert check_ip_literal_urls([Link("https://198-51-100-42.example/login")]) == []
