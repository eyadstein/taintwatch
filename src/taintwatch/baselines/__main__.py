"""Quick comparison: ``python -m taintwatch.baselines [--defenses SPEC ...]``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from taintwatch.baselines.registry import DEFAULT_SPECS, build_defense
from taintwatch.baselines.run import run_defended
from taintwatch.bench import build_suite
from taintwatch.guard import ConfirmFn
from taintwatch.policy import Verdict

WIDTHS = (20, 16, 16, 22)


def _approve(tool: str, verdict: Verdict) -> bool:
    return True


def _rate(hits: int, total: int) -> float:
    return hits / total if total else 0.0


def _row(cells: Sequence[str]) -> str:
    rest = zip(cells[1:], WIDTHS[1:], strict=True)
    return cells[0].ljust(WIDTHS[0]) + "".join(cell.rjust(width) for cell, width in rest)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taintwatch.baselines", description="Compare defenses on the benchmark."
    )
    parser.add_argument("--attacks", type=int, default=600)
    parser.add_argument("--benign", type=int, default=200)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--confirm", action="store_true", help="auto-approve confirm verdicts")
    parser.add_argument("--defenses", nargs="+", default=list(DEFAULT_SPECS))
    args = parser.parse_args(argv)
    try:
        suite = build_suite(args.attacks, args.benign, args.seed)
        defenses = [build_defense(spec) for spec in args.defenses]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    confirm: ConfirmFn | None = _approve if args.confirm else None

    print(f"{len(suite.attacks)} attacks, {len(suite.benign)} benign tasks, seed {args.seed}")
    print(_row(["defense", "attack success", "benign utility", "utility under attack"]))
    for defense in defenses:
        attack_runs = [
            run_defended(s, defense, seed=args.seed, confirm=confirm) for s in suite.attacks
        ]
        benign_runs = [
            run_defended(s, defense, seed=args.seed, confirm=confirm) for s in suite.benign
        ]
        success = _rate(sum(o.attack_succeeded for o in attack_runs), len(attack_runs))
        benign = _rate(sum(o.utility_ok for o in benign_runs), len(benign_runs))
        under_attack = _rate(sum(o.utility_ok for o in attack_runs), len(attack_runs))
        print(_row([defense.name, f"{success:.1%}", f"{benign:.1%}", f"{under_attack:.1%}"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
