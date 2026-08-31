"""Offline URL extraction and structural phishing heuristics."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser
from urllib.parse import urlparse

from .common import organizational_domain
from .models import Finding


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SHORTENER_DOMAINS = {
    "bit.do",
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}
PROTECTED_DOMAINS = {
    "amazon.com",
    "apple.com",
    "docusign.com",
    "dropbox.com",
    "github.com",
    "google.com",
    "microsoft.com",
    "okta.com",
    "paypal.com",
}

HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
        "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Χ": "x",
        "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    }
)


@dataclass(frozen=True)
class Link:
    url: str
    text: str = ""
    source: str = "plain"


class AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        self._href = dict(attrs).get("href")
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            href = self._href.strip()
            if href.lower().startswith(("http://", "https://")):
                self.links.append(Link(href, " ".join(self._text).strip(), "html"))
            self._href = None
            self._text = []


def _part_text(part: Message) -> str:
    try:
        return str(part.get_content())
    except (LookupError, UnicodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def extract_links(message: Message) -> list[Link]:
    """Extract HTTP(S) destinations and preserve visible HTML anchor text."""

    links: list[Link] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        text = _part_text(part)
        if content_type == "text/html":
            parser = AnchorParser()
            try:
                parser.feed(text)
                parser.close()
                links.extend(parser.links)
            except (ValueError, AssertionError):
                pass
        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(".,);!?]}")
            if not any(link.url == url for link in links):
                links.append(Link(url, "", "plain" if content_type == "text/plain" else "html-source"))

    unique: list[Link] = []
    seen: set[tuple[str, str]] = set()
    for link in links:
        key = (link.url, link.text)
        if key not in seen:
            seen.add(key)
            unique.append(link)
    return unique


def hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def displayed_hostname(text: str) -> str:
    compact = text.strip().strip("<>[](){}.,;:!")
    match = re.search(r"(?:https?://|www\.)[^\s<>]+", compact, re.I)
    if not match:
        return ""
    candidate = match.group(0)
    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate
    return hostname(candidate)


def _unicode_domain(domain: str) -> str:
    labels: list[str] = []
    for label in domain.split("."):
        try:
            labels.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def _skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).translate(HOMOGLYPHS)
    return "".join(char.lower() for char in normalized if char.isalnum())


def _levenshtein(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, 1):
        current = [index]
        for offset, right_char in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[offset] + 1, previous[offset - 1] + (left_char != right_char)))
        previous = current
    return previous[-1]


def looks_like_protected_domain(domain: str) -> str:
    """Return the imitated protected domain, or an empty string."""

    registrable = organizational_domain(domain)
    if registrable in PROTECTED_DOMAINS:
        return ""
    unicode_domain = _unicode_domain(registrable)
    candidate_label = unicode_domain.split(".", 1)[0]
    candidate = _skeleton(candidate_label)
    for protected in PROTECTED_DOMAINS:
        protected_label = protected.split(".", 1)[0]
        target = _skeleton(protected_label)
        if candidate == target or _levenshtein(candidate, target) <= 1:
            return protected
        if len(target) >= 5 and (candidate.startswith(target) or target in candidate):
            return protected
    return ""


def check_link_text_mismatch(links: list[Link]) -> list[Finding]:
    mismatches: list[str] = []
    for link in links:
        shown = displayed_hostname(link.text)
        actual = hostname(link.url)
        if shown and actual and organizational_domain(shown) != organizational_domain(actual):
            mismatches.append(f"Shown {shown} but opens {actual}")
    if not mismatches:
        return []
    return [
        Finding(
            rule_id="url.link_text_mismatch",
            category="URLs",
            title="Link text hides a different destination",
            explanation="At least one link visually names one domain but actually points to another.",
            weight=18,
            evidence=tuple(mismatches[:5]),
        )
    ]


def check_url_shorteners(links: list[Link]) -> list[Finding]:
    matches = sorted({hostname(link.url) for link in links if hostname(link.url) in SHORTENER_DOMAINS})
    if not matches:
        return []
    return [
        Finding(
            rule_id="url.shortener",
            category="URLs",
            title="Shortened URL obscures its final destination",
            explanation="A URL-shortening service prevents the recipient from seeing the destination domain before visiting it.",
            weight=12,
            evidence=tuple(matches),
        )
    ]


def check_lookalike_domains(links: list[Link]) -> list[Finding]:
    matches: list[str] = []
    for link in links:
        domain = hostname(link.url)
        imitated = looks_like_protected_domain(domain)
        if domain and (domain.startswith("xn--") or any(label.startswith("xn--") for label in domain.split(".")) or imitated):
            description = f"{domain} resembles {imitated}" if imitated else f"{domain} uses internationalized-domain encoding"
            if description not in matches:
                matches.append(description)
    if not matches:
        return []
    return [
        Finding(
            rule_id="url.lookalike_domain",
            category="URLs",
            title="URL may imitate a trusted domain",
            explanation="A destination uses a close spelling, homoglyph, or encoded international character that can be mistaken for a familiar domain.",
            weight=20,
            evidence=tuple(matches[:5]),
        )
    ]


def check_ip_literal_urls(links: list[Link]) -> list[Finding]:
    matches: list[str] = []
    for link in links:
        domain = hostname(link.url)
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            continue
        if domain not in matches:
            matches.append(domain)
    if not matches:
        return []
    return [
        Finding(
            rule_id="url.ip_literal",
            category="URLs",
            title="URL uses a raw IP address",
            explanation="The link bypasses a normal named domain and points directly to a network address, which is unusual for legitimate account pages.",
            weight=20,
            evidence=tuple(matches[:5]),
        )
    ]


URL_RULES = (check_link_text_mismatch, check_url_shorteners, check_lookalike_domains, check_ip_literal_urls)


def run_url_rules(links: list[Link]) -> list[Finding]:
    return [finding for rule in URL_RULES for finding in rule(links)]
