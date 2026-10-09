"""Compile a policy syntax tree into the runtime ``Policy`` representation."""

from __future__ import annotations

from enum import IntEnum
from typing import TypeVar

from taintwatch.dsl.errors import DslError
from taintwatch.dsl.nodes import Condition, Program, RuleNode
from taintwatch.labels import Confidentiality, Integrity
from taintwatch.policy import Action, Policy, Rule

L = TypeVar("L", bound=IntEnum)


def _level(enum_type: type[L], cond: Condition) -> L:
    try:
        return enum_type[cond.level.upper()]
    except KeyError:
        valid = ", ".join(m.name.lower() for m in enum_type)
        raise DslError(
            f"unknown {cond.subject} level {cond.level!r}; expected one of: {valid}",
            cond.line,
            cond.col,
        ) from None


def _integrity_floor(cond: Condition) -> Integrity:
    """Translate ``integrity < L`` / ``<= L`` into the minimum acceptable integrity."""
    if cond.op not in ("<", "<="):
        raise DslError("integrity conditions use '<' or '<='", cond.line, cond.col)
    level = _level(Integrity, cond)
    if cond.op == "<":
        return level
    if level is Integrity.SYSTEM:
        raise DslError("'integrity <= system' is always true", cond.line, cond.col)
    return Integrity(level + 1)


def _confidentiality_ceiling(cond: Condition) -> Confidentiality:
    """Translate ``confidentiality > L`` / ``>= L`` into the maximum allowed level."""
    if cond.op not in (">", ">="):
        raise DslError("confidentiality conditions use '>' or '>='", cond.line, cond.col)
    level = _level(Confidentiality, cond)
    if cond.op == ">":
        return level
    if level is Confidentiality.PUBLIC:
        raise DslError("'confidentiality >= public' is always true", cond.line, cond.col)
    return Confidentiality(level - 1)


def compile_rule(node: RuleNode) -> Rule:
    min_integrity: Integrity | None = None
    max_confidentiality: Confidentiality | None = None
    for cond in node.conditions:
        if cond.subject == "integrity":
            if min_integrity is not None:
                raise DslError("at most one integrity condition per rule", cond.line, cond.col)
            min_integrity = _integrity_floor(cond)
        else:
            if max_confidentiality is not None:
                raise DslError(
                    "at most one confidentiality condition per rule", cond.line, cond.col
                )
            max_confidentiality = _confidentiality_ceiling(cond)
    return Rule(
        name=node.name,
        tool=node.tool,
        arg=node.arg,
        min_integrity=min_integrity,
        max_confidentiality=max_confidentiality,
        action=Action[node.action.upper()],
        reason=node.reason,
    )


def compile_program(program: Program) -> Policy:
    return Policy(compile_rule(node) for node in program.rules)
