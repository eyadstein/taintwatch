"""Bridge between ``TStr`` and the ``Guard`` provenance graph."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from taintwatch.guard import Guard
from taintwatch.labels import Confidentiality, Integrity
from taintwatch.provenance import NodeKind
from taintwatch.spans.tstr import TStr
from taintwatch.tainted import Labeled


def ingest_text(
    guard: Guard,
    text: str,
    *,
    source: str,
    integrity: Integrity,
    confidentiality: Confidentiality = Confidentiality.PUBLIC,
) -> Labeled[TStr]:
    """Register external text; every character carries the source label."""
    base = guard.ingest(
        text, source=source, integrity=integrity, confidentiality=confidentiality
    )
    return Labeled(TStr.of(text, base.label), base.node_id, base.label)


def derive_text(
    guard: Guard, value: TStr, parents: Sequence[Labeled[Any]], description: str
) -> Labeled[TStr]:
    """Register text built from ``parents``.

    The label is the join of the labels *inside* ``value``, so text that was cut
    away (sliced off, split off or redacted) no longer taints the result.
    """
    label = value.overall_label()
    node = guard.graph.add(
        NodeKind.DERIVED, label, description, tuple(p.node_id for p in parents)
    )
    return Labeled(value, node.id, label)
