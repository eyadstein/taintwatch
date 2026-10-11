"""Analysis commands: ``sweeps`` writes sweeps.csv, ``notebooks`` regenerates the notebooks."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from taintwatch.analysis.notebooks import build_notebooks
from taintwatch.analysis.sweeps import (
    REFERENCE_SPECS,
    SCORER_THRESHOLDS,
    SPOTLIGHT_RESISTS,
    run_specs,
    run_sweep,
    write_points_csv,
)
from taintwatch.bench import build_suite
from taintwatch.guard import ConfirmFn
from taintwatch.policy import Verdict


def _approve(tool: str, verdict: Verdict) -> bool:
    return True


def _sweeps(args: argparse.Namespace) -> int:
    try:
        suite = build_suite(args.attacks, args.benign, args.seed)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    confirm: ConfirmFn | None = _approve if args.confirm else None
    scenarios = suite.scenarios
    points = [
        *run_specs(REFERENCE_SPECS, scenarios, seed=args.seed, confirm=confirm),
        *run_sweep("scorer", SCORER_THRESHOLDS, scenarios, seed=args.seed, confirm=confirm),
        *run_sweep("spotlight", SPOTLIGHT_RESISTS, scenarios, seed=args.seed, confirm=confirm),
    ]
    write_points_csv(points, args.out)
    for p in points:
        attack = p.attack_success.percent()
        print(f"{p.defense:<20} attack {attack:>7}  benign {p.benign_utility.percent():>7}")
    print(f"wrote {len(points)} points to {args.out}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m taintwatch.analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    sweeps = sub.add_parser("sweeps", help="sweep scorer and spotlight parameters")
    sweeps.add_argument("--attacks", type=int, default=600)
    sweeps.add_argument("--benign", type=int, default=200)
    sweeps.add_argument("--seed", type=int, default=7)
    sweeps.add_argument("--confirm", action="store_true", help="auto-approve confirm verdicts")
    sweeps.add_argument("--out", default="results/sweeps.csv")
    notebooks = sub.add_parser("notebooks", help="regenerate the notebooks")
    notebooks.add_argument("--out", default="notebooks")
    args = parser.parse_args(argv)
    if args.command == "notebooks":
        for path in build_notebooks(args.out):
            print(f"wrote {path}")
        return 0
    return _sweeps(args)


if __name__ == "__main__":
    raise SystemExit(main())
