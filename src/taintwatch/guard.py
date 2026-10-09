"""The runtime guard: ingest data, derive new data, and gate tool calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from taintwatch.errors import TaintwatchError
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.policy import Action, Policy, Verdict
from taintwatch.provenance import NodeKind, ProvenanceGraph
from taintwatch.tainted import Labeled

T = TypeVar("T")
R = TypeVar("R")

ConfirmFn = Callable[[str, Verdict], bool]


class PolicyViolation(TaintwatchError):
    """A tool call was refused by policy."""

    def __init__(self, tool: str, verdict: Verdict) -> None:
        super().__init__(f"tool call {tool!r} blocked: {verdict.explain()}")
        self.tool = tool
        self.verdict = verdict


@dataclass(frozen=True, slots=True)
class AuditRecord:
    tool: str
    arg_nodes: tuple[tuple[str, str], ...]
    verdict: Verdict


class Guard:
    def __init__(
        self,
        policy: Policy,
        graph: ProvenanceGraph | None = None,
        confirm: ConfirmFn | None = None,
    ) -> None:
        self._policy = policy
        self._graph = graph if graph is not None else ProvenanceGraph()
        self._confirm = confirm
        self._audit: list[AuditRecord] = []

    @property
    def graph(self) -> ProvenanceGraph:
        return self._graph

    @property
    def audit(self) -> tuple[AuditRecord, ...]:
        return tuple(self._audit)

    def ingest(
        self,
        value: T,
        *,
        source: str,
        integrity: Integrity,
        confidentiality: Confidentiality = Confidentiality.PUBLIC,
    ) -> Labeled[T]:
        """Register data entering the agent from an external source."""
        label = Label(integrity, confidentiality, frozenset({source}))
        node = self._graph.add(NodeKind.SOURCE, label, source)
        return Labeled(value, node.id, label)

    def derive(
        self, value: T, parents: Sequence[Labeled[Any]], description: str
    ) -> Labeled[T]:
        """Register a value computed from other labeled values."""
        label = Label.join_all(p.label for p in parents)
        node = self._graph.add(
            NodeKind.DERIVED, label, description, tuple(p.node_id for p in parents)
        )
        return Labeled(value, node.id, label)

    def check(self, tool: str, args: Mapping[str, Labeled[Any]]) -> Verdict:
        """Evaluate a prospective tool call and record it in the audit log."""
        verdict = self._policy.evaluate(tool, args)
        arg_nodes = tuple((name, labeled.node_id) for name, labeled in args.items())
        self._audit.append(AuditRecord(tool, arg_nodes, verdict))
        return verdict

    def call(
        self,
        tool: str,
        args: Mapping[str, Labeled[Any]],
        fn: Callable[..., R],
        *,
        output_integrity: Integrity = Integrity.TOOL_OUTPUT,
    ) -> Labeled[R]:
        """Run ``fn`` only if policy permits; label and track its result."""
        verdict = self.check(tool, args)
        if verdict.action is Action.BLOCK:
            raise PolicyViolation(tool, verdict)
        if verdict.action is Action.CONFIRM and (
            self._confirm is None or not self._confirm(tool, verdict)
        ):
            raise PolicyViolation(tool, verdict)

        result = fn(**{name: labeled.value for name, labeled in args.items()})
        label = Label.join_all(a.label for a in args.values()).cap_integrity(output_integrity)
        node = self._graph.add(
            NodeKind.TOOL_RESULT,
            label,
            f"result of {tool}",
            tuple(a.node_id for a in args.values()),
        )
        return Labeled(result, node.id, label)
