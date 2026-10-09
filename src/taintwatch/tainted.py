"""A value bundled with its label and its place in the provenance graph."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from taintwatch.labels import Label

T = TypeVar("T")


@dataclass(frozen=True)
class Labeled(Generic[T]):
    value: T
    node_id: str
    label: Label
