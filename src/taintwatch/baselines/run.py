"""Run a benchmark scenario under a defense."""

from __future__ import annotations

import random

from taintwatch.agent import AgentRuntime, build_standard_registry
from taintwatch.baselines.defense import Defense
from taintwatch.bench import Outcome, Scenario
from taintwatch.guard import ConfirmFn, Guard


def run_defended(
    scenario: Scenario,
    defense: Defense,
    *,
    seed: int = 0,
    confirm: ConfirmFn | None = None,
    gullible: bool = True,
    max_steps: int = 20,
) -> Outcome:
    """Run ``scenario`` in a fresh world. Randomness depends only on seed, defense and scenario."""
    world = scenario.build_world()
    guard = Guard(defense.policy, confirm=confirm)
    runtime = AgentRuntime(build_standard_registry(world), guard, max_steps=max_steps)
    rng = random.Random(f"{seed}:{defense.name}:{scenario.id}")
    agent = defense.wrap(scenario.build_agent(gullible=gullible), rng)
    result = runtime.run(agent, scenario.task)
    return Outcome(scenario, world, result)
