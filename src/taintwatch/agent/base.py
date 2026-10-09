"""Core types shared by agents and the runtime."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from taintwatch.spans import TStr


class Status(StrEnum):
    OK = "ok"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ToolRequest:
    """An agent's request to call a tool. Arguments keep their span labels."""

    tool: str
    args: dict[str, TStr]


@dataclass(frozen=True, slots=True)
class Finish:
    answer: TStr


Decision = ToolRequest | Finish


@dataclass(frozen=True, slots=True)
class Observation:
    """What the agent sees after a request: tool output or a notice."""

    tool: str
    output: TStr
    status: Status
    node_id: str | None = None


class Agent(Protocol):
    def decide(self, task: TStr, observations: Sequence[Observation]) -> Decision: ...
