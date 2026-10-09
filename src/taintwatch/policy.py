"""Declarative policies: which labeled data may flow into which tool arguments."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum, IntEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, TypeVar

from taintwatch.errors import PolicyError
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.tainted import Labeled

E = TypeVar("E", bound=Enum)


class Action(IntEnum):
    """Ordered by severity so the strictest violated rule wins."""

    ALLOW = 0
    CONFIRM = 1
    BLOCK = 2


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    tool: str
    arg: str = "*"
    min_integrity: Integrity | None = None
    max_confidentiality: Confidentiality | None = None
    action: Action = Action.BLOCK
    reason: str = ""

    def applies_to(self, tool: str, arg: str) -> bool:
        return fnmatchcase(tool, self.tool) and fnmatchcase(arg, self.arg)

    def violated_by(self, label: Label) -> bool:
        if self.min_integrity is not None and label.integrity < self.min_integrity:
            return True
        return (
            self.max_confidentiality is not None
            and label.confidentiality > self.max_confidentiality
        )


@dataclass(frozen=True, slots=True)
class Violation:
    rule: Rule
    arg: str
    label: Label


@dataclass(frozen=True, slots=True)
class Verdict:
    action: Action
    violations: tuple[Violation, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    def explain(self) -> str:
        if not self.violations:
            return "no policy violations"
        return "; ".join(
            f"{v.rule.name} (arg {v.arg!r}: integrity={v.label.integrity.name}, "
            f"confidentiality={v.label.confidentiality.name})"
            for v in self.violations
        )


_KNOWN_FIELDS = frozenset(
    {"name", "tool", "arg", "min_integrity", "max_confidentiality", "action", "reason"}
)


def _parse_enum(enum_type: type[E], value: object, field_name: str) -> E | None:
    if value is None:
        return None
    try:
        return enum_type[str(value).upper()]
    except KeyError:
        valid = ", ".join(m.name.lower() for m in enum_type)
        raise PolicyError(
            f"invalid {field_name} {value!r}; expected one of: {valid}"
        ) from None


def _parse_rule(raw: Mapping[str, Any]) -> Rule:
    unknown = set(raw) - _KNOWN_FIELDS
    if unknown:
        raise PolicyError(f"unknown rule field(s): {', '.join(sorted(unknown))}")
    for required in ("name", "tool"):
        if required not in raw:
            raise PolicyError(f"rule is missing required field {required!r}")
    action = _parse_enum(Action, raw.get("action"), "action")
    return Rule(
        name=str(raw["name"]),
        tool=str(raw["tool"]),
        arg=str(raw.get("arg", "*")),
        min_integrity=_parse_enum(Integrity, raw.get("min_integrity"), "min_integrity"),
        max_confidentiality=_parse_enum(
            Confidentiality, raw.get("max_confidentiality"), "max_confidentiality"
        ),
        action=Action.BLOCK if action is None else action,
        reason=str(raw.get("reason", "")),
    )


class Policy:
    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules = tuple(rules)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    @classmethod
    def from_toml(cls, text: str) -> Policy:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise PolicyError(f"policy is not valid TOML: {exc}") from exc
        return cls(_parse_rule(raw) for raw in data.get("rule", []))

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        return cls.from_toml(Path(path).read_text(encoding="utf-8"))

    def evaluate(self, tool: str, args: Mapping[str, Labeled[Any]]) -> Verdict:
        violations: list[Violation] = []
        for arg_name, labeled in args.items():
            for rule in self._rules:
                if rule.applies_to(tool, arg_name) and rule.violated_by(labeled.label):
                    violations.append(Violation(rule, arg_name, labeled.label))
        action = max((v.rule.action for v in violations), default=Action.ALLOW)
        return Verdict(action, tuple(violations))


DEFAULT_POLICY_TOML = """
[[rule]]
name = "untrusted-input-to-shell"
tool = "shell.*"
min_integrity = "user"
action = "block"
reason = "Shell commands must not be influenced by untrusted content."

[[rule]]
name = "untrusted-email-recipient"
tool = "email.send"
arg = "to"
min_integrity = "user"
action = "block"
reason = "Only the user may choose who receives email."

[[rule]]
name = "secret-leaves-via-email"
tool = "email.send"
max_confidentiality = "internal"
action = "block"

[[rule]]
name = "secret-leaves-via-http"
tool = "http.*"
max_confidentiality = "internal"
action = "block"

[[rule]]
name = "untrusted-file-write"
tool = "fs.write"
arg = "content"
min_integrity = "tool_output"
action = "confirm"
"""


def default_policy() -> Policy:
    return Policy.from_toml(DEFAULT_POLICY_TOML)
