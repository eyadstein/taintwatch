"""The Taintwatch policy language: parse, validate and compile policies."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from taintwatch.dsl.compiler import compile_program, compile_rule
from taintwatch.dsl.errors import DslError
from taintwatch.dsl.nodes import Condition, Program, RuleNode
from taintwatch.dsl.parser import parse
from taintwatch.dsl.validator import Diagnostic, Severity, check
from taintwatch.policy import Policy


def lint(text: str, known_tools: Iterable[str] = ()) -> list[Diagnostic]:
    """Parse and statically check policy source. Raises ``DslError`` on bad syntax."""
    return check(parse(text), known_tools)


def compile_policy(text: str) -> Policy:
    """Parse, reject policies with errors, and compile to a runtime ``Policy``."""
    program = parse(text)
    for diagnostic in check(program):
        if diagnostic.severity is Severity.ERROR:
            raise DslError(diagnostic.message, diagnostic.line, 1)
    return compile_program(program)


def load_policy(path: str | Path) -> Policy:
    return compile_policy(Path(path).read_text(encoding="utf-8"))


__all__ = [
    "Condition",
    "Diagnostic",
    "DslError",
    "Program",
    "RuleNode",
    "Severity",
    "check",
    "compile_policy",
    "compile_program",
    "compile_rule",
    "lint",
    "load_policy",
    "parse",
]
