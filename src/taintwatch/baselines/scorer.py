"""Heuristic scorer baseline: sum the weights of matched features against a threshold."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Feature:
    name: str
    pattern: re.Pattern[str]
    weight: float


def _feature(name: str, pattern: str, weight: float) -> Feature:
    return Feature(name, re.compile(pattern, re.IGNORECASE | re.DOTALL), weight)


DEFAULT_FEATURES: tuple[Feature, ...] = (
    _feature(
        "override",
        r"\b(?:ignore|disregard|forget)\b[^.\n]{0,30}\b(?:previous|prior|above|earlier|all)\b",
        3.0,
    ),
    _feature(
        "authority",
        r"\b(?:system (?:notice|override|message)|administrators?|admin note)\b",
        2.0,
    ),
    _feature(
        "urgency",
        r"\b(?:important|urgent|immediately|before continuing|before you answer)\b",
        1.0,
    ),
    _feature(
        "direct_address",
        r"\b(?:you must|you should|you need to|could you also|please also)\b|\bassistant,",
        1.5,
    ),
    _feature(
        "shell_payload",
        r"\|\s*(?:ba)?sh\b|\brm\s+-rf\b|\bnc\s+-e\b|\bchmod\s+-R\b|\b(?:curl|wget)\s+https?://",
        2.5,
    ),
    _feature("hidden_markup", r"<!--.*?-->", 1.0),
    _feature("credential_ask", r"\b(?:passwords?|api key|credentials?|secret)\b", 1.0),
    _feature("external_link", r"""https?://[^\s"'>]+""", 0.5),
)


class HeuristicScorer:
    """Each feature counts once, however many times it matches."""

    def __init__(
        self, features: Sequence[Feature] = DEFAULT_FEATURES, threshold: float = 2.5
    ) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        self._features = tuple(features)
        self._threshold = threshold

    @property
    def threshold(self) -> float:
        return self._threshold

    def matched(self, text: str) -> list[Feature]:
        return [f for f in self._features if f.pattern.search(text) is not None]

    def score(self, text: str) -> float:
        return sum(f.weight for f in self.matched(text))

    def flags(self, text: str) -> bool:
        return self.score(text) >= self._threshold
