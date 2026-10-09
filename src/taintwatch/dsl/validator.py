"""Static checks for policies: catch mistakes before they reach production."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase

from taintwatch.dsl.compiler import compile_rule
from taintwatch.dsl.nodes import Program
from taintwatch.labels import Confidentiality, Integrity
from taintwatch.policy import Rule


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class Diagnostic:
    severity: Severity
    message: str
    line: int
    rule: str = ""

    def __str__(self) -> str:
        where = f"line {self.line}" if self.line else "policy"
        return f"{self.severity.value}: {where}: {self.message}"


def _covers(wide: Rule, narrow: Rule) -> bool:
    """True if ``wide`` fires whenever ``narrow`` fires and is at least as strict."""
    if wide.action < narrow.action:
        return False
    if not (fnmatchcase(narrow.tool, wide.tool) and fnmatchcase(narrow.arg, wide.arg)):
        return False
    if narrow.min_integrity is not None and (
        wide.min_integrity is None or wide.min_integrity < narrow.min_integrity
    ):
        return False
    return not (
        narrow.max_confidentiality is not None
        and (
            wide.max_confidentiality is None
            or wide.max_confidentiality > narrow.max_confidentiality
        )
    )


def check(program: Program, known_tools: Iterable[str] = ()) -> list[Diagnostic]:
    """Lint a parsed policy. ``known_tools`` enables tool-coverage checks."""
    tools = tuple(known_tools)
    found: list[Diagnostic] = []
    first_seen: dict[str, int] = {}
    compiled = []
    for node in program.rules:
        if node.name in first_seen:
            found.append(
                Diagnostic(
                    Severity.ERROR,
                    f"duplicate rule name {node.name!r} "
                    f"(first defined on line {first_seen[node.name]})",
                    node.line,
                    node.name,
                )
            )
        else:
            first_seen[node.name] = node.line
        compiled.append((node, compile_rule(node)))

    for node, rule in compiled:
        if rule.min_integrity is Integrity.UNTRUSTED:
            found.append(
                Diagnostic(
                    Severity.WARNING,
                    f"rule {rule.name!r}: integrity condition can never be true "
                    "(nothing ranks below 'untrusted')",
                    node.line,
                    rule.name,
                )
            )
        if rule.max_confidentiality is Confidentiality.SECRET:
            found.append(
                Diagnostic(
                    Severity.WARNING,
                    f"rule {rule.name!r}: confidentiality condition can never be true "
                    "(nothing ranks above 'secret')",
                    node.line,
                    rule.name,
                )
            )
        if tools and not any(fnmatchcase(t, rule.tool) for t in tools):
            found.append(
                Diagnostic(
                    Severity.WARNING,
                    f"rule {rule.name!r}: tool pattern {rule.tool!r} matches no known tool",
                    node.line,
                    rule.name,
                )
            )

    for i, (node, rule) in enumerate(compiled):
        for j, (_, other) in enumerate(compiled):
            if i == j or not _covers(other, rule):
                continue
            if not _covers(rule, other) or j < i:
                found.append(
                    Diagnostic(
                        Severity.WARNING,
                        f"rule {rule.name!r} is redundant: {other.name!r} already covers it",
                        node.line,
                        rule.name,
                    )
                )
                break

    for tool in tools:
        if not any(fnmatchcase(tool, rule.tool) for _, rule in compiled):
            found.append(Diagnostic(Severity.WARNING, f"known tool {tool!r} has no rule", 0))
    return sorted(found, key=lambda d: (d.line, d.message))
