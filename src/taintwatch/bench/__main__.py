"""Generate the benchmark: ``python -m taintwatch.bench [--attacks N] [--benign N]``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from taintwatch.bench.suite import build_suite, write_jsonl


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taintwatch.bench", description="Generate benchmark scenarios."
    )
    parser.add_argument("--attacks", type=int, default=600)
    parser.add_argument("--benign", type=int, default=200)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", default="data/scenarios.jsonl")
    args = parser.parse_args(argv)
    try:
        suite = build_suite(args.attacks, args.benign, args.seed)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    written = write_jsonl(suite.scenarios, args.out)
    print(f"wrote {written} scenarios to {args.out}")
    for family, count in suite.counts().items():
        print(f"  {family}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
