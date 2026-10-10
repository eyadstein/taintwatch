"""Aggregate run records into per-defense summaries and breakdowns."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from taintwatch.evaluation.runner import RunRecord
from taintwatch.evaluation.stats import Rate, mcnemar_exact, median, percentile


@dataclass(frozen=True, slots=True)
class DefenseSummary:
    defense: str
    attack_success: Rate
    utility_under_attack: Rate
    benign_utility: Rate
    benign_blocked: Rate
    latency_median_ms: float
    latency_p95_ms: float
    overhead: float | None


@dataclass(frozen=True, slots=True)
class PairedResult:
    """Attack outcomes of defense ``a`` against defense ``b`` on the same scenarios."""

    a: str
    b: str
    only_a: int
    only_b: int
    p_value: float


def _group(records: Sequence[RunRecord]) -> dict[str, list[RunRecord]]:
    groups: dict[str, list[RunRecord]] = {}
    for record in records:
        groups.setdefault(record.defense, []).append(record)
    return groups


def summarize(records: Sequence[RunRecord], reference: str = "none") -> list[DefenseSummary]:
    """One summary per defense, in order of first appearance.

    ``overhead`` is the defense's median latency divided by the reference defense's.
    """
    groups = _group(records)
    reference_rows = groups.get(reference)
    reference_median = (
        median([r.latency_ms for r in reference_rows]) if reference_rows else None
    )
    summaries: list[DefenseSummary] = []
    for name, rows in groups.items():
        attacks = [r for r in rows if r.is_attack]
        benign = [r for r in rows if not r.is_attack]
        latencies = [r.latency_ms for r in rows]
        middle = median(latencies)
        summaries.append(
            DefenseSummary(
                defense=name,
                attack_success=Rate(sum(r.attack_succeeded for r in attacks), len(attacks)),
                utility_under_attack=Rate(sum(r.utility_ok for r in attacks), len(attacks)),
                benign_utility=Rate(sum(r.utility_ok for r in benign), len(benign)),
                benign_blocked=Rate(sum(1 for r in benign if r.blocked > 0), len(benign)),
                latency_median_ms=middle,
                latency_p95_ms=percentile(latencies, 95),
                overhead=middle / reference_median if reference_median else None,
            )
        )
    return summaries


def attack_breakdown(records: Sequence[RunRecord], defense: str, key: str) -> dict[str, Rate]:
    """Attack success rate per value of a scenario tag (``goal``, ``carrier``, ``style``...)."""
    groups: dict[str, list[bool]] = {}
    for record in records:
        if record.defense == defense and record.is_attack:
            groups.setdefault(record.tag(key, "?"), []).append(record.attack_succeeded)
    return {value: Rate(sum(flags), len(flags)) for value, flags in sorted(groups.items())}


def benign_breakdown(records: Sequence[RunRecord], defense: str) -> dict[str, Rate]:
    """Benign utility per scenario family."""
    groups: dict[str, list[bool]] = {}
    for record in records:
        if record.defense == defense and not record.is_attack:
            groups.setdefault(record.family, []).append(record.utility_ok)
    return {family: Rate(sum(flags), len(flags)) for family, flags in sorted(groups.items())}


def paired_attack_comparison(records: Sequence[RunRecord], a: str, b: str) -> PairedResult:
    """Compare which attacks succeed under ``a`` versus ``b``, scenario by scenario."""
    by_a = {r.scenario_id: r.attack_succeeded for r in records if r.defense == a and r.is_attack}
    by_b = {r.scenario_id: r.attack_succeeded for r in records if r.defense == b and r.is_attack}
    shared = by_a.keys() & by_b.keys()
    only_a = sum(1 for sid in shared if by_a[sid] and not by_b[sid])
    only_b = sum(1 for sid in shared if by_b[sid] and not by_a[sid])
    return PairedResult(a, b, only_a, only_b, mcnemar_exact(only_a, only_b))


def compare_to_pivot(
    records: Sequence[RunRecord], names: Sequence[str], pivot: str
) -> list[PairedResult]:
    """Paired comparisons of every other defense against ``pivot``."""
    if pivot not in names:
        return []
    return [paired_attack_comparison(records, name, pivot) for name in names if name != pivot]
