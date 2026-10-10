"""Run a scenario under a defense and store the full trace."""

from __future__ import annotations

from typing import Any

from taintwatch.baselines import build_defense, run_defended
from taintwatch.bench import Scenario
from taintwatch.guard import ConfirmFn
from taintwatch.policy import Verdict
from taintwatch.server.store import NewEvent, NewRun, TraceStore
from taintwatch.spans import TStr


def _approve(tool: str, verdict: Verdict) -> bool:
    return True


def context_segments(text: TStr) -> list[dict[str, Any]]:
    """Serialize labeled text as segments the trace viewer can color by integrity."""
    return [
        {
            "text": text.text[seg.start : seg.end],
            "integrity": seg.label.integrity.name,
            "confidentiality": seg.label.confidentiality.name,
            "sources": sorted(seg.label.sources),
        }
        for seg in text.segments
    ]


def record_run(
    store: TraceStore,
    scenario: Scenario,
    defense_spec: str,
    *,
    seed: int = 7,
    confirm: bool = False,
) -> int:
    """Run ``scenario`` under ``defense_spec`` and return the stored run id.

    Raises ``ValueError`` for an unknown or malformed defense spec.
    """
    defense = build_defense(defense_spec)
    confirm_fn: ConfirmFn | None = _approve if confirm else None
    outcome = run_defended(scenario, defense, seed=seed, confirm=confirm_fn)
    result = outcome.result
    events = tuple(
        NewEvent(e.step, e.kind.value, e.tool, e.args, e.detail) for e in result.events
    )
    return store.add_run(
        NewRun(
            scenario_id=scenario.id,
            family=scenario.family,
            defense=defense.name,
            task=scenario.task,
            seed=seed,
            is_attack=scenario.is_attack,
            attack_succeeded=outcome.attack_succeeded,
            utility_ok=outcome.utility_ok,
            blocked=result.blocked,
            calls=result.calls,
            steps=result.steps,
            truncated=result.truncated,
            answer=str(result.answer),
            context=context_segments(result.context),
            events=events,
        )
    )
