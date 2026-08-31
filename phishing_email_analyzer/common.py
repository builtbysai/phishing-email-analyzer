"""Shared parsing helpers with no I/O or third-party dependencies."""

from __future__ import annotations

import re
from email.message import Message
from html.parser import HTMLParser


MULTI_LABEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "com.au",
    "net.au",
    "co.jp",
    "co.nz",
    "com.br",
    "com.sg",
}


def organizational_domain(domain: str) -> str:
    """Return a pragmatic registrable-domain approximation.

    A full public-suffix list would require a dependency or network access. The
    compact suffix set covers common multi-label cases and keeps runtime fully
    offline.
    """

    labels = domain.lower().strip(". ").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


class VisibleTextParser(HTMLParser):
    """Collect visible-ish text while ignoring style and script blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)

    def text(self) -> str:
        return " ".join(part.strip() for part in self.parts if part.strip())


def html_to_text(value: str) -> str:
    parser = VisibleTextParser()
    try:
        parser.feed(value)
        parser.close()
    except (ValueError, AssertionError):
        return re.sub(r"<[^>]+>", " ", value)
    return parser.text()


def message_body_text(message: Message) -> str:
    """Return concatenated plain text and visible HTML from non-attachments."""

    parts: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            value = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            value = payload.decode("utf-8", errors="replace")
        if part.get_content_type() == "text/html":
            value = html_to_text(str(value))
        parts.append(str(value))
    return "\n".join(parts)
