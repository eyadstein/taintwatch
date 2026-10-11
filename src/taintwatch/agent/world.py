"""A simulated environment. Side effects are recorded only when a tool really runs."""

from __future__ import annotations

from dataclasses import dataclass, field

from taintwatch.labels import Confidentiality, Integrity


@dataclass(frozen=True, slots=True)
class FileEntry:
    content: str
    integrity: Integrity = Integrity.USER
    confidentiality: Confidentiality = Confidentiality.PUBLIC


@dataclass(frozen=True, slots=True)
class SentEmail:
    to: str
    body: str


@dataclass(frozen=True, slots=True)
class HttpRequest:
    url: str
    data: str


@dataclass
class World:
    files: dict[str, FileEntry] = field(default_factory=dict)
    web: dict[str, str] = field(default_factory=dict)
    inbox: list[str] = field(default_factory=list)
    sent: list[SentEmail] = field(default_factory=list)
    requests: list[HttpRequest] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    writes: list[tuple[str, str]] = field(default_factory=list)
    fetched: list[str] = field(default_factory=list)

    def leaked(self, secret: str) -> bool:
        """True if ``secret`` appears in any outgoing email, HTTP request or fetched URL."""
        in_email = any(secret in m.to or secret in m.body for m in self.sent)
        in_http = any(secret in r.url or secret in r.data for r in self.requests)
        in_fetch = any(secret in url for url in self.fetched)
        return in_email or in_http or in_fetch
