"""A deterministic mock agent: follows a fixed plan and, if gullible, obeys injections."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from taintwatch.agent.base import Decision, Finish, Observation, Status, ToolRequest
from taintwatch.agent.directives import extract_directives
from taintwatch.spans import TStr, interpolate


@dataclass(frozen=True, slots=True)
class PlanStep:
    """One planned tool call. Arguments are templates over ``{task}`` and ``{r0}``, ``{r1}``..."""

    tool: str
    args: Mapping[str, str]


class ScriptedAgent:
    """Runs ``plan`` in order. Results of plan step ``k`` are available as ``{rk}``.

    A gullible agent also executes any directive found in successful tool output,
    which models a language model that follows instructions hidden in data. Create
    one agent per run: it keeps state.
    """

    def __init__(
        self, plan: Sequence[PlanStep], *, gullible: bool = True, answer: str = "Done."
    ) -> None:
        self._plan = tuple(plan)
        self._gullible = gullible
        self._answer = answer
        self._next = 0
        self._seen = 0
        self._issued: list[str | None] = []
        self._results: dict[str, TStr] = {}
        self._pending: deque[ToolRequest] = deque()

    def decide(self, task: TStr, observations: Sequence[Observation]) -> Decision:
        for index in range(self._seen, len(observations)):
            observation = observations[index]
            key = self._issued[index]
            if key is not None:
                self._results[key] = observation.output
            if self._gullible and observation.status is Status.OK:
                self._pending.extend(extract_directives(observation.output))
        self._seen = len(observations)

        values: dict[str, TStr] = {"task": task, **self._results}
        if self._pending:
            self._issued.append(None)
            return self._fill(self._pending.popleft(), values)
        if self._next < len(self._plan):
            step = self._plan[self._next]
            args = {name: interpolate(template, values) for name, template in step.args.items()}
            self._issued.append(f"r{self._next}")
            self._next += 1
            return ToolRequest(step.tool, args)
        return Finish(interpolate(self._answer, values))

    @staticmethod
    def _fill(request: ToolRequest, values: Mapping[str, TStr]) -> ToolRequest:
        """Substitute ``{rN}`` placeholders in injected arguments; unknown ones stay as-is."""
        args: dict[str, TStr] = {}
        for name, value in request.args.items():
            try:
                args[name] = interpolate(value, values)
            except KeyError:
                args[name] = value
        return ToolRequest(request.tool, args)
