"""Provenance graph: a DAG recording where every value came from."""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import count

from taintwatch.labels import Label


class NodeKind(StrEnum):
    SOURCE = "source"
    DERIVED = "derived"
    TOOL_RESULT = "tool_result"


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    kind: NodeKind
    label: Label
    description: str
    parents: tuple[str, ...] = ()


class ProvenanceGraph:
    """Append-only graph. Parents must exist first, so cycles are impossible."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._counter = count(1)

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._nodes

    def add(
        self,
        kind: NodeKind,
        label: Label,
        description: str,
        parents: Sequence[str] = (),
    ) -> Node:
        for parent in parents:
            if parent not in self._nodes:
                raise KeyError(f"unknown parent node: {parent}")
        node = Node(
            id=f"n{next(self._counter)}",
            kind=kind,
            label=label,
            description=description,
            parents=tuple(parents),
        )
        self._nodes[node.id] = node
        return node

    def get(self, node_id: str) -> Node:
        return self._nodes[node_id]

    def ancestors(self, node_id: str) -> list[Node]:
        """Everything ``node_id`` depends on, nearest first, excluding itself."""
        start = self.get(node_id)
        seen = {start.id}
        found: list[Node] = []
        queue: deque[str] = deque(start.parents)
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            node = self._nodes[current]
            found.append(node)
            queue.extend(node.parents)
        return found

    def sources_of(self, node_id: str) -> list[Node]:
        """The original input sources behind a value."""
        start = self.get(node_id)
        if start.kind is NodeKind.SOURCE:
            return [start]
        return [n for n in self.ancestors(node_id) if n.kind is NodeKind.SOURCE]
