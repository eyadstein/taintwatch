"""Run every scenario under every defense and record one row per run."""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass

from taintwatch.baselines import Defense, run_defended
from taintwatch.bench import Outcome, Scenario
from taintwatch.evaluation.stats import median
from taintwatch.guard import ConfirmFn


@dataclass(frozen=True, slots=True)
class RunRecord:
    defense: str
    scenario_id: str
    family: str
    is_attack: bool
    attack_succeeded: bool
    utility_ok: bool
    blocked: int
    calls: int
    steps: int
    latency_ms: float
    tags: tuple[tuple[str, str], ...] = ()

    def tag(self, key: str, default: str = "") -> str:
        return dict(self.tags).get(key, default)


def _timed(
    scenario: Scenario,
    defense: Defense,
    seed: int,
    confirm: ConfirmFn | None,
    gullible: bool,
) -> tuple[Outcome, float]:
    start = time.perf_counter()
    outcome = run_defended(scenario, defense, seed=seed, confirm=confirm, gullible=gullible)
    return outcome, (time.perf_counter() - start) * 1000.0


def evaluate(
    scenarios: Sequence[Scenario],
    defenses: Sequence[Defense],
    *,
    seed: int = 7,
    confirm: ConfirmFn | None = None,
    repeats: int = 1,
    gullible: bool = True,
) -> list[RunRecord]:
    """Run each scenario under each defense, defense by defense.

    Outcomes are deterministic. ``repeats`` only affects latency, which is the median
    wall-clock time over the repeated runs.
    """
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    records: list[RunRecord] = []
    for defense in defenses:
        for scenario in scenarios:
            outcome, first = _timed(scenario, defense, seed, confirm, gullible)
            timings = [first]
            for _ in range(repeats - 1):
                timings.append(_timed(scenario, defense, seed, confirm, gullible)[1])
            result = outcome.result
            records.append(
                RunRecord(
                    defense=defense.name,
                    scenario_id=scenario.id,
                    family=scenario.family,
                    is_attack=scenario.is_attack,
                    attack_succeeded=outcome.attack_succeeded,
                    utility_ok=outcome.utility_ok,
                    blocked=result.blocked,
                    calls=result.calls,
                    steps=result.steps,
                    latency_ms=median(timings),
                    tags=scenario.meta,
                )
            )
    return records
