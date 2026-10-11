"""Parameter sweeps over defenses, for sensitivity and trade-off analysis."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from taintwatch.baselines import build_defense
from taintwatch.bench import Scenario
from taintwatch.evaluation import Rate, evaluate, summarize
from taintwatch.guard import ConfirmFn

SCORER_THRESHOLDS = (0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0)
SPOTLIGHT_RESISTS = (0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 1.0)
REFERENCE_SPECS = ("none", "taintwatch", "taintwatch-coarse", "keyword")
FIELDS = ("defense", "param", "attack_hits", "attack_total", "benign_hits", "benign_total")


@dataclass(frozen=True, slots=True)
class SweepPoint:
    """One defense configuration: its attack success and benign utility."""

    defense: str
    param: float | None
    attack_success: Rate
    benign_utility: Rate


def _measure(
    spec: str,
    param: float | None,
    scenarios: Sequence[Scenario],
    seed: int,
    confirm: ConfirmFn | None,
) -> SweepPoint:
    defense = build_defense(spec)
    records = evaluate(scenarios, [defense], seed=seed, confirm=confirm)
    summary = summarize(records)[0]
    return SweepPoint(defense.name, param, summary.attack_success, summary.benign_utility)


def run_specs(
    specs: Sequence[str],
    scenarios: Sequence[Scenario],
    *,
    seed: int = 7,
    confirm: ConfirmFn | None = None,
) -> list[SweepPoint]:
    """Measure each defense spec once. The points carry no parameter."""
    if not scenarios:
        raise ValueError("scenarios must not be empty")
    return [_measure(spec, None, scenarios, seed, confirm) for spec in specs]


def run_sweep(
    family: str,
    params: Sequence[float],
    scenarios: Sequence[Scenario],
    *,
    seed: int = 7,
    confirm: ConfirmFn | None = None,
) -> list[SweepPoint]:
    """Measure ``family@param`` (for example ``scorer@2.5``) for every parameter."""
    if not scenarios:
        raise ValueError("scenarios must not be empty")
    return [_measure(f"{family}@{p:g}", p, scenarios, seed, confirm) for p in params]


def _dominates(a: SweepPoint, b: SweepPoint) -> bool:
    attack_a, attack_b = a.attack_success.value, b.attack_success.value
    benign_a, benign_b = a.benign_utility.value, b.benign_utility.value
    no_worse = attack_a <= attack_b and benign_a >= benign_b
    better = attack_a < attack_b or benign_a > benign_b
    return no_worse and better


def pareto_front(points: Sequence[SweepPoint]) -> list[SweepPoint]:
    """Points that no other point beats on both attack success and benign utility."""
    front = [p for p in points if not any(_dominates(q, p) for q in points)]
    return sorted(front, key=lambda p: (p.attack_success.value, -p.benign_utility.value))


def write_points_csv(points: Sequence[SweepPoint], path: str | Path) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        for p in points:
            writer.writerow(
                {
                    "defense": p.defense,
                    "param": "" if p.param is None else repr(p.param),
                    "attack_hits": p.attack_success.hits,
                    "attack_total": p.attack_success.total,
                    "benign_hits": p.benign_utility.hits,
                    "benign_total": p.benign_utility.total,
                }
            )
    return len(points)


def read_points_csv(path: str | Path) -> list[SweepPoint]:
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return [
            SweepPoint(
                defense=row["defense"],
                param=float(row["param"]) if row["param"] else None,
                attack_success=Rate(int(row["attack_hits"]), int(row["attack_total"])),
                benign_utility=Rate(int(row["benign_hits"]), int(row["benign_total"])),
            )
            for row in csv.DictReader(handle)
        ]
