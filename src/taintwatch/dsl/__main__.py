"""Command line linter: ``python -m taintwatch.dsl FILE [KNOWN_TOOL ...]``."""

from __future__ import annotations

import sys
from pathlib import Path

from taintwatch.dsl import DslError, Severity, lint


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python -m taintwatch.dsl FILE [KNOWN_TOOL ...]", file=sys.stderr)
        return 2
    text = Path(argv[0]).read_text(encoding="utf-8")
    try:
        diagnostics = lint(text, argv[1:])
    except DslError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for diagnostic in diagnostics:
        print(diagnostic)
    return 1 if any(d.severity is Severity.ERROR for d in diagnostics) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
