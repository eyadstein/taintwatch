"""Small statistics helpers: confidence intervals, percentiles and an exact paired test."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

Z95 = 1.959963984540054


def wilson_interval(successes: int, total: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a proportion. Well behaved at 0 and at ``total``."""
    if total <= 0:
        raise ValueError("total must be positive")
    if not 0 <= successes <= total:
        raise ValueError("successes must be between 0 and total")
    p = successes / total
    z2 = z * z
    denom = 1 + z2 / total
    centre = (p + z2 / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


@dataclass(frozen=True, slots=True)
class Rate:
    """``hits`` out of ``total`` runs."""

    hits: int
    total: int

    @property
    def value(self) -> float:
        return self.hits / self.total if self.total else 0.0

    def interval(self) -> tuple[float, float]:
        if self.total == 0:
            return (0.0, 1.0)
        return wilson_interval(self.hits, self.total)

    def percent(self) -> str:
        return "n/a" if self.total == 0 else f"{self.value:.1%}"

    def fmt(self) -> str:
        """Percentage with its 95% interval, e.g. ``27.0% [23.6%, 30.7%]``."""
        if self.total == 0:
            return "n/a"
        low, high = self.interval()
        return f"{self.value:.1%} [{low:.1%}, {high:.1%}]"

    def to_dict(self) -> dict[str, float]:
        low, high = self.interval()
        return {
            "hits": self.hits,
            "total": self.total,
            "rate": self.value,
            "lo": low,
            "hi": high,
        }


def percentile(values: Sequence[float], q: float) -> float:
    """The ``q``-th percentile (0 to 100) with linear interpolation."""
    if not values:
        raise ValueError("no values")
    if not 0 <= q <= 100:
        raise ValueError("q must be between 0 and 100")
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q / 100
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def median(values: Sequence[float]) -> float:
    return percentile(values, 50)


def mcnemar_exact(only_a: int, only_b: int) -> float:
    """Two-sided exact McNemar p-value from the two discordant counts."""
    if only_a < 0 or only_b < 0:
        raise ValueError("counts must not be negative")
    n = only_a + only_b
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(only_a, only_b) + 1))
    return min(1.0, 2 * tail / (1 << n))
