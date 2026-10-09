"""Error type for the policy language."""

from __future__ import annotations

from taintwatch.errors import PolicyError


class DslError(PolicyError):
    """A syntax or semantic error in a policy file, with its position."""

    def __init__(self, message: str, line: int, col: int) -> None:
        super().__init__(f"line {line}, column {col}: {message}")
        self.message = message
        self.line = line
        self.col = col
