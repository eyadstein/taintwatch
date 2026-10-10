"""A defense: a policy for the guard plus an optional wrapper around the agent."""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field

from taintwatch.agent import Agent
from taintwatch.policy import Policy

Wrapper = Callable[[Agent, random.Random], Agent]


@dataclass(frozen=True, slots=True)
class Defense:
    """Everything the benchmark needs to run a scenario under one defense.

    ``policy`` is enforced by the runtime's guard (empty means no enforcement).
    ``wrapper`` lets a defense sit between the tools and the agent, which is where
    prompt-level defenses such as filters and spotlighting operate.
    """

    name: str
    description: str
    policy: Policy = field(default_factory=Policy)
    wrapper: Wrapper | None = None

    def wrap(self, agent: Agent, rng: random.Random) -> Agent:
        return agent if self.wrapper is None else self.wrapper(agent, rng)
