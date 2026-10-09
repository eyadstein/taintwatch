"""Inspect and sanitize labeled text."""

from __future__ import annotations

from dataclasses import dataclass

from taintwatch.labels import Integrity
from taintwatch.spans.tstr import TStr


@dataclass(frozen=True, slots=True)
class Excerpt:
    """A run of low-integrity text and the sources it came from."""

    start: int
    end: int
    text: str
    sources: frozenset[str]


def untrusted_excerpts(text: TStr, floor: Integrity, limit: int = 80) -> list[Excerpt]:
    """Describe each run of text below ``floor``; long runs are shortened to ``limit``."""
    if limit < 4:
        raise ValueError("limit must be at least 4")
    found: list[Excerpt] = []
    for start, end in text.ranges_below(floor):
        raw = text.text[start:end]
        shown = raw if len(raw) <= limit else raw[: limit - 3] + "..."
        found.append(Excerpt(start, end, shown, text[start:end].overall_label().sources))
    return found


def redact_below(text: TStr, floor: Integrity, placeholder: str = "[REDACTED]") -> TStr:
    """Replace every run of text below ``floor`` with a trusted placeholder."""
    result = TStr.of("")
    pos = 0
    for start, end in text.ranges_below(floor):
        result = result + text[pos:start] + placeholder
        pos = end
    return result + text[pos:]
