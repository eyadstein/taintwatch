"""Labels for structured (JSON-like) data."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from taintwatch.labels import Integrity, Label
from taintwatch.spans.tstr import TStr

T = TypeVar("T")


@dataclass(frozen=True)
class Tagged(Generic[T]):
    """A non-string leaf (number, bool, None) carrying a label."""

    value: T
    label: Label


def wrap(value: Any, label: Label) -> Any:
    """Attach ``label`` to every leaf. Strings become ``TStr``; existing labels are kept.

    Dict keys are not tracked.
    """
    if isinstance(value, TStr | Tagged):
        return value
    if isinstance(value, str):
        return TStr.of(value, label)
    if isinstance(value, Mapping):
        return {key: wrap(item, label) for key, item in value.items()}
    if isinstance(value, list):
        return [wrap(item, label) for item in value]
    if isinstance(value, tuple):
        return tuple(wrap(item, label) for item in value)
    return Tagged(value, label)


def unwrap(value: Any) -> Any:
    """Strip all labels, returning plain JSON-like data."""
    if isinstance(value, TStr):
        return value.text
    if isinstance(value, Tagged):
        return value.value
    if isinstance(value, Mapping):
        return {key: unwrap(item) for key, item in value.items()}
    if isinstance(value, list):
        return [unwrap(item) for item in value]
    if isinstance(value, tuple):
        return tuple(unwrap(item) for item in value)
    return value


def join_label(value: Any) -> Label:
    """Join of every label inside ``value``. Unlabeled plain values count as literals."""
    if isinstance(value, TStr):
        return value.overall_label()
    if isinstance(value, Tagged):
        return value.label
    if isinstance(value, Mapping):
        return Label.join_all(join_label(item) for item in value.values())
    if isinstance(value, list | tuple | set | frozenset):
        return Label.join_all(join_label(item) for item in value)
    return Label()


def leaves(value: Any, path: str = "$") -> Iterator[tuple[str, Label]]:
    """Yield ``(path, label)`` for every leaf, e.g. ``$.items[0].name``."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from leaves(item, f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from leaves(item, f"{path}[{index}]")
    else:
        yield path, join_label(value)


def untrusted_paths(value: Any, floor: Integrity) -> list[str]:
    """Paths of leaves whose integrity is below ``floor``."""
    return [path for path, label in leaves(value) if label.integrity < floor]
