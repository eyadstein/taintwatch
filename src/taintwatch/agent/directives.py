"""Directives: the mock model's stand-in for 'the LLM obeyed an injected instruction'.

Format: ``<<call tool.name key="value" key2="value2">>``. Argument values are slices
of the original labeled text, so they keep the labels of whoever wrote them.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from taintwatch.agent.base import ToolRequest
from taintwatch.spans import TStr

_CALL = re.compile(r'<<call\s+([\w.]+)((?:\s+\w+="[^"]*")*)\s*>>')
_ARG = re.compile(r'(\w+)="([^"]*)"')


def extract_directives(text: TStr) -> list[ToolRequest]:
    """Find every directive in ``text``; argument values keep their span labels."""
    requests: list[ToolRequest] = []
    for call in _CALL.finditer(text.text):
        base = call.start(2)
        args: dict[str, TStr] = {}
        for arg in _ARG.finditer(call.group(2)):
            args[arg.group(1)] = text[base + arg.start(2) : base + arg.end(2)]
        requests.append(ToolRequest(call.group(1), args))
    return requests


def render_directive(tool: str, args: Mapping[str, str]) -> str:
    """Build directive text, e.g. for generating injection payloads."""
    parts = [f"<<call {tool}"]
    for name, value in args.items():
        if not name.isidentifier():
            raise ValueError(f"invalid argument name {name!r}")
        if '"' in value:
            raise ValueError("directive values cannot contain double quotes")
        parts.append(f'{name}="{value}"')
    return " ".join(parts) + ">>"
