"""Syntax tree for the Taintwatch policy language."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Condition:
    """``subject op level``, e.g. ``integrity < user``."""

    subject: str
    op: str
    level: str
    line: int
    col: int


@dataclass(frozen=True, slots=True)
class RuleNode:
    name: str
    action: str
    tool: str
    arg: str
    conditions: tuple[Condition, ...]
    reason: str
    line: int
    col: int


@dataclass(frozen=True, slots=True)
class Program:
    rules: tuple[RuleNode, ...]
