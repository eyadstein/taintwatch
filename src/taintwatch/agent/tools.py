"""Tool declarations and the tool registry."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass

from taintwatch.errors import TaintwatchError
from taintwatch.labels import Confidentiality, Integrity

_NAME = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")


class ToolError(TaintwatchError):
    """Base class for tool and registry errors."""


class ToolArgumentError(ToolError):
    """A tool was called with missing or unexpected arguments."""


class UnknownToolError(ToolError):
    """No tool is registered under the requested name."""


@dataclass(frozen=True, slots=True)
class ToolOutput:
    """What a tool returns, together with the trust level it declares for it."""

    text: str
    integrity: Integrity = Integrity.TOOL_OUTPUT
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    source: str = ""


@dataclass(frozen=True, slots=True)
class Tool:
    name: str
    params: tuple[str, ...]
    fn: Callable[..., ToolOutput]
    description: str = ""

    def check_args(self, names: Iterable[str]) -> None:
        given = set(names)
        missing = sorted(set(self.params) - given)
        extra = sorted(given - set(self.params))
        parts: list[str] = []
        if missing:
            parts.append(f"missing argument(s): {', '.join(missing)}")
        if extra:
            parts.append(f"unexpected argument(s): {', '.join(extra)}")
        if parts:
            raise ToolArgumentError(f"tool {self.name!r}: " + "; ".join(parts))

    def invoke(self, args: Mapping[str, str]) -> ToolOutput:
        self.check_args(args)
        return self.fn(**args)


class ToolRegistry:
    def __init__(self, tools: Iterable[Tool] = ()) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        if _NAME.fullmatch(tool.name) is None:
            raise ToolError(f"invalid tool name {tool.name!r}; expected 'namespace.action'")
        if tool.name in self._tools:
            raise ToolError(f"tool {tool.name!r} is already registered")
        self._tools[tool.name] = tool

    def find(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def get(self, name: str) -> Tool:
        tool = self._tools.get(name)
        if tool is None:
            raise UnknownToolError(f"unknown tool {name!r}")
        return tool

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())
