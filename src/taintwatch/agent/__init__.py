"""Mock agent runtime, tool registry and simulated world."""

from __future__ import annotations

from taintwatch.agent.base import Agent, Decision, Finish, Observation, Status, ToolRequest
from taintwatch.agent.directives import extract_directives, render_directive
from taintwatch.agent.runtime import (
    DEFAULT_SYSTEM_PROMPT,
    AgentRuntime,
    Event,
    EventKind,
    RunResult,
)
from taintwatch.agent.scripted import PlanStep, ScriptedAgent
from taintwatch.agent.stdtools import build_standard_registry
from taintwatch.agent.tools import (
    Tool,
    ToolArgumentError,
    ToolError,
    ToolOutput,
    ToolRegistry,
    UnknownToolError,
)
from taintwatch.agent.world import FileEntry, HttpRequest, SentEmail, World

__all__ = [
    "DEFAULT_SYSTEM_PROMPT",
    "Agent",
    "AgentRuntime",
    "Decision",
    "Event",
    "EventKind",
    "FileEntry",
    "Finish",
    "HttpRequest",
    "Observation",
    "PlanStep",
    "RunResult",
    "ScriptedAgent",
    "SentEmail",
    "Status",
    "Tool",
    "ToolArgumentError",
    "ToolError",
    "ToolOutput",
    "ToolRegistry",
    "ToolRequest",
    "UnknownToolError",
    "World",
    "build_standard_registry",
    "extract_directives",
    "render_directive",
]
