"""Keyword-filter baseline: flag text that contains any suspicious phrase."""

from __future__ import annotations

from collections.abc import Sequence

DEFAULT_PHRASES: tuple[str, ...] = (
    "ignore previous",
    "ignore all",
    "ignore the above",
    "disregard",
    "new instructions",
    "system notice",
    "system override",
    "administrator",
    "you must",
    "before you answer",
    "before continuing",
    "curl ",
    "wget ",
    "| sh",
    "rm -rf",
    "nc -e",
    "chmod -r",
    "ssh-rsa",
    "password",
)


class KeywordFilter:
    """Case-insensitive substring matching. Deliberately simple."""

    def __init__(self, phrases: Sequence[str] = DEFAULT_PHRASES) -> None:
        cleaned = tuple(phrase.lower() for phrase in phrases)
        if not cleaned or any(not phrase.strip() for phrase in cleaned):
            raise ValueError("phrases must be a non-empty list of non-blank strings")
        self._phrases = cleaned

    @property
    def phrases(self) -> tuple[str, ...]:
        return self._phrases

    def matches(self, text: str) -> list[str]:
        lowered = text.lower()
        return [phrase for phrase in self._phrases if phrase in lowered]

    def flags(self, text: str) -> bool:
        lowered = text.lower()
        return any(phrase in lowered for phrase in self._phrases)
