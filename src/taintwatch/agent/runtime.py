"""Agent runtime: drives an agent against tools through the Guard."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from taintwatch.agent.base import Agent, Finish, Observation, Status, ToolRequest
from taintwatch.agent.tools import Tool, ToolArgumentError, ToolOutput, ToolRegistry
from taintwatch.guard import Guard, PolicyViolation
from taintwatch.labels import Integrity, Label
from taintwatch.spans import TStr, derive_text, ingest_text
from taintwatch.tainted import Labeled

DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant with access to tools."


class EventKind(StrEnum):
    CALL = "call"
    BLOCKED = "blocked"
    ERROR = "error"
    FINISH = "finish"


@dataclass(frozen=True, slots=True)
class Event:
    step: int
    kind: EventKind
    tool: str = ""
    args: tuple[tuple[str, str], ...] = ()
    detail: str = ""


@dataclass(frozen=True, slots=True)
class RunResult:
    answer: TStr
    context: TStr
    events: tuple[Event, ...]
    truncated: bool

    def count(self, kind: EventKind) -> int:
        return sum(1 for event in self.events if event.kind is kind)

    @property
    def steps(self) -> int:
        return max((event.step for event in self.events), default=0)

    @property
    def calls(self) -> int:
        return self.count(EventKind.CALL)

    @property
    def blocked(self) -> int:
        return self.count(EventKind.BLOCKED)

    @property
    def errors(self) -> int:
        return self.count(EventKind.ERROR)


def _runner(tool: Tool) -> Callable[..., ToolOutput]:
    def run(**kwargs: TStr) -> ToolOutput:
        return tool.invoke({name: str(value) for name, value in kwargs.items()})

    return run


def _error(
    step: int,
    request: ToolRequest,
    arg_view: tuple[tuple[str, str], ...],
    message: str,
    events: list[Event],
) -> tuple[Observation, Labeled[TStr] | None]:
    events.append(Event(step, EventKind.ERROR, request.tool, arg_view, message))
    return Observation(request.tool, TStr.of(f"[error: {message}]"), Status.ERROR), None


class AgentRuntime:
    def __init__(
        self,
        registry: ToolRegistry,
        guard: Guard,
        *,
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        max_steps: int = 20,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self._registry = registry
        self._guard = guard
        self._max_steps = max_steps
        self._system = TStr.of(
            system_prompt, Label(Integrity.SYSTEM, sources=frozenset({"system"}))
        )

    def run(self, agent: Agent, task_text: str) -> RunResult:
        """Run ``agent`` on ``task_text`` until it finishes or hits ``max_steps``."""
        task = ingest_text(self._guard, task_text, source="user", integrity=Integrity.USER)
        context = self._system + "\nUser: " + task.value + "\n"
        nodes: list[Labeled[TStr]] = [task]
        observations: list[Observation] = []
        events: list[Event] = []
        for step in range(1, self._max_steps + 1):
            decision = agent.decide(task.value, tuple(observations))
            if isinstance(decision, Finish):
                events.append(Event(step, EventKind.FINISH))
                final = context + "\nAssistant: " + decision.answer
                return RunResult(decision.answer, final, tuple(events), False)
            observation, node = self._execute(step, decision, nodes, events)
            observations.append(observation)
            if node is not None:
                nodes.append(node)
            context = context + "\n[" + decision.tool + "] " + observation.output + "\n"
        return RunResult(TStr.of("[max steps reached]"), context, tuple(events), True)

    def _label_arg(self, value: TStr, nodes: Sequence[Labeled[TStr]]) -> Labeled[TStr]:
        sources = value.overall_label().sources
        parents = [node for node in nodes if node.label.sources & sources]
        return derive_text(self._guard, value, parents, "tool argument")

    def _execute(
        self,
        step: int,
        request: ToolRequest,
        nodes: Sequence[Labeled[TStr]],
        events: list[Event],
    ) -> tuple[Observation, Labeled[TStr] | None]:
        arg_view = tuple((name, str(value)) for name, value in request.args.items())
        tool = self._registry.find(request.tool)
        if tool is None:
            return _error(step, request, arg_view, f"unknown tool {request.tool!r}", events)
        try:
            tool.check_args(request.args)
        except ToolArgumentError as exc:
            return _error(step, request, arg_view, str(exc), events)

        labeled_args = {
            name: self._label_arg(value, nodes) for name, value in request.args.items()
        }
        try:
            result = self._guard.call(
                request.tool, labeled_args, _runner(tool), output_integrity=Integrity.SYSTEM
            )
        except PolicyViolation as exc:
            detail = exc.verdict.explain()
            events.append(Event(step, EventKind.BLOCKED, request.tool, arg_view, detail))
            notice = TStr.of(f"[blocked by policy: {detail}]")
            return Observation(request.tool, notice, Status.BLOCKED), None

        output = result.value
        content = self._guard.ingest(
            output.text,
            source=output.source or f"tool:{request.tool}",
            integrity=output.integrity,
            confidentiality=output.confidentiality,
        )
        label = result.label.join(content.label)
        parents: list[Labeled[Any]] = [result, content]
        node = derive_text(
            self._guard, TStr.of(output.text, label), parents, f"output of {request.tool}"
        )
        events.append(Event(step, EventKind.CALL, request.tool, arg_view))
        return Observation(request.tool, node.value, Status.OK, node.node_id), node
