"""Run one scenario against a policy and report what happened."""

from __future__ import annotations

from dataclasses import dataclass

from taintwatch.agent import AgentRuntime, RunResult, World, build_standard_registry
from taintwatch.bench.scenario import Scenario
from taintwatch.guard import ConfirmFn, Guard
from taintwatch.policy import Policy


@dataclass(frozen=True, slots=True)
class Outcome:
    scenario: Scenario
    world: World
    result: RunResult

    @property
    def attack_succeeded(self) -> bool:
        attack = self.scenario.attack
        return attack is not None and attack.holds(self.world, str(self.result.answer))

    @property
    def utility_ok(self) -> bool:
        utility = self.scenario.utility
        return utility is None or utility.holds(self.world, str(self.result.answer))


def run_scenario(
    scenario: Scenario,
    policy: Policy,
    *,
    confirm: ConfirmFn | None = None,
    gullible: bool = True,
    max_steps: int = 20,
) -> Outcome:
    """Run ``scenario`` in a fresh world. An empty ``Policy()`` means no defense."""
    world = scenario.build_world()
    guard = Guard(policy, confirm=confirm)
    runtime = AgentRuntime(build_standard_registry(world), guard, max_steps=max_steps)
    result = runtime.run(scenario.build_agent(gullible=gullible), scenario.task)
    return Outcome(scenario, world, result)
