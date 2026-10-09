"""Security labels and the lattice operations defined over them.

Integrity answers "how much can this value be trusted?" (higher is better).
Confidentiality answers "how secret is this value?" (higher is more secret).
Combining values lowers integrity and raises confidentiality, so taint only
ever spreads.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum


class Integrity(IntEnum):
    UNTRUSTED = 0
    TOOL_OUTPUT = 1
    USER = 2
    SYSTEM = 3


class Confidentiality(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


@dataclass(frozen=True, slots=True)
class Label:
    """Integrity, confidentiality and the set of sources that influenced a value."""

    integrity: Integrity = Integrity.SYSTEM
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    sources: frozenset[str] = frozenset()

    def join(self, other: Label) -> Label:
        """Least upper bound: the label of a value derived from both inputs."""
        return Label(
            integrity=min(self.integrity, other.integrity),
            confidentiality=max(self.confidentiality, other.confidentiality),
            sources=self.sources | other.sources,
        )

    def cap_integrity(self, ceiling: Integrity) -> Label:
        """Return a label whose integrity is at most ``ceiling``."""
        if self.integrity <= ceiling:
            return self
        return Label(ceiling, self.confidentiality, self.sources)

    @staticmethod
    def join_all(labels: Iterable[Label]) -> Label:
        """Join any number of labels. Joining nothing yields the bottom label."""
        result = Label()
        for label in labels:
            result = result.join(label)
        return result
