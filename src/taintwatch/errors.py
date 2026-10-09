"""Exception types shared across Taintwatch."""

from __future__ import annotations


class TaintwatchError(Exception):
    """Base class for all Taintwatch errors."""


class PolicyError(TaintwatchError):
    """Raised when a policy definition is malformed."""
