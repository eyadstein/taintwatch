"""Run the evaluation: ``python -m taintwatch.evaluation [--defenses SPEC ...]``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from taintwatch.baselines import DEFAULT_SPECS, build_defense
from taintwatch.bench import build_suite
from taintwatch.evaluation.metrics import compare_to_pivot, summarize
from taintwatch.evaluation.report import PIVOT, render_markdown, write_csv, write_json
from taintwatch.evaluation.runner import evaluate
from taintwatch.guard import ConfirmFn
from taintwatch.policy import Verdict


def _approve(tool: str, verdict: Verdict) -> bool:
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taintwatch.evaluation", description="Evaluate defenses on the benchmark."
    )
    parser.add_argument("--attacks", type=int, default=600)
    parser.add_argument("--benign", type=int, default=200)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--repeats", type=int, default=3, help="timing repeats per run")
    parser.add_argument("--confirm", action="store_true", help="auto-approve confirm verdicts")
    parser.add_argument("--defenses", nargs="+", default=list(DEFAULT_SPECS))
    parser.add_argument("--out", default="results")
    args = parser.parse_args(argv)
    confirm: ConfirmFn | None = _approve if args.confirm else None
    try:
        suite = build_suite(args.attacks, args.benign, args.seed)
        defenses = [build_defense(spec) for spec in args.defenses]
        records = evaluate(
            suite.scenarios, defenses, seed=args.seed, confirm=confirm, repeats=args.repeats
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summaries = summarize(records)
    names = [s.defense for s in summaries]
    comparisons = compare_to_pivot(records, names, PIVOT)
    out = Path(args.out)
    write_csv(records, out / "records.csv")
    config = {
        "seed": args.seed,
        "attacks": args.attacks,
        "benign": args.benign,
        "repeats": args.repeats,
        "confirm": args.confirm,
    }
    write_json(out / "summary.json", config, summaries, comparisons)
    markdown = render_markdown(records, summaries)
    (out / "report.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"wrote {len(records)} runs to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
