"""Agent wrappers that implement non-policy defenses at the observation boundary."""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence

from taintwatch.agent import Agent, Decision, Finish, Observation, Status, ToolRequest
from taintwatch.baselines.defense import Wrapper
from taintwatch.labels import Integrity
from taintwatch.spans import TStr

FILTER_NOTICE = "[content removed by filter]"
Transform = Callable[[int, Observation], Observation]


class ObservationFilterAgent:
    """Rewrites each observation exactly once before the wrapped agent sees it."""

    def __init__(self, inner: Agent, transform: Transform) -> None:
        self._inner = inner
        self._transform = transform
        self._seen: list[Observation] = []

    def decide(self, task: TStr, observations: Sequence[Observation]) -> Decision:
        for index in range(len(self._seen), len(observations)):
            self._seen.append(self._transform(index, observations[index]))
        return self._inner.decide(task, tuple(self._seen[: len(observations)]))


class ContextTaintAgent:
    """Ablation: label every outgoing call with the join of everything seen so far.

    This is what you get from taint tracking at the level of the whole context
    instead of individual spans.
    """

    def __init__(self, inner: Agent) -> None:
        self._inner = inner

    def decide(self, task: TStr, observations: Sequence[Observation]) -> Decision:
        decision = self._inner.decide(task, observations)
        if isinstance(decision, Finish):
            return decision
        context = task.overall_label()
        for observation in observations:
            context = context.join(observation.output.overall_label())
        args = {name: TStr.of(value.text, context) for name, value in decision.args.items()}
        return ToolRequest(decision.tool, args)


def detector_wrapper(detector: Callable[[str], bool]) -> Wrapper:
    """Remove the text of every successful tool output that ``detector`` flags."""

    def wrap(agent: Agent, rng: random.Random) -> Agent:
        def transform(index: int, observation: Observation) -> Observation:
            if observation.status is Status.OK and detector(observation.output.text):
                return Observation(
                    observation.tool,
                    TStr.of(FILTER_NOTICE),
                    Status.BLOCKED,
                    observation.node_id,
                )
            return observation

        return ObservationFilterAgent(agent, transform)

    return wrap


def spotlight_wrapper(resist: float) -> Wrapper:
    """Model spotlighting: untrusted output is treated as data with probability ``resist``.

    The mock agent never obeys directives found in a non-OK observation, so re-labelling
    the observation keeps the text available as content while disabling its directives.
    """

    def wrap(agent: Agent, rng: random.Random) -> Agent:
        def transform(index: int, observation: Observation) -> Observation:
            untrusted = observation.output.overall_label().integrity < Integrity.USER
            if observation.status is Status.OK and untrusted and rng.random() < resist:
                return Observation(
                    observation.tool, observation.output, Status.ERROR, observation.node_id
                )
            return observation

        return ObservationFilterAgent(agent, transform)

    return wrap


def context_taint_wrapper(agent: Agent, rng: random.Random) -> Agent:
    return ContextTaintAgent(agent)
