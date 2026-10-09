import pytest

from taintwatch.labels import Label
from taintwatch.provenance import NodeKind, ProvenanceGraph


def build() -> tuple[ProvenanceGraph, str, str, str, str]:
    graph = ProvenanceGraph()
    s1 = graph.add(NodeKind.SOURCE, Label(), "web page")
    s2 = graph.add(NodeKind.SOURCE, Label(), "user prompt")
    d1 = graph.add(NodeKind.DERIVED, Label(), "summary", (s1.id, s2.id))
    d2 = graph.add(NodeKind.DERIVED, Label(), "command", (d1.id,))
    return graph, s1.id, s2.id, d1.id, d2.id


def test_ancestors_are_nearest_first() -> None:
    graph, s1, s2, d1, d2 = build()
    assert [n.id for n in graph.ancestors(d2)] == [d1, s1, s2]


def test_sources_of_derived_value() -> None:
    graph, s1, s2, _, d2 = build()
    assert [n.id for n in graph.sources_of(d2)] == [s1, s2]


def test_sources_of_a_source_is_itself() -> None:
    graph, s1, *_ = build()
    assert [n.id for n in graph.sources_of(s1)] == [s1]


def test_unknown_parent_is_rejected() -> None:
    graph = ProvenanceGraph()
    with pytest.raises(KeyError):
        graph.add(NodeKind.DERIVED, Label(), "orphan", ("n999",))
