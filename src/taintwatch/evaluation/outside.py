"""Evaluate defenses on attacks outside the default policy's guarded sinks.

``python -m taintwatch.evaluation.outside [--defenses SPEC ...]``
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from taintwatch.baselines import build_defense
from taintwatch.bench import generate_benign, generate_outside_attacks
from taintwatch.evaluation.metrics import summarize
from taintwatch.evaluation.report import render_markdown, write_csv
from taintwatch.evaluation.runner import evaluate
from taintwatch.guard import ConfirmFn
from taintwatch.policy import Verdict

OUTSIDE_SPECS = ("none", "taintwatch", "taintwatch-strict", "keyword", "scorer")
TITLE = "Taintwatch: attacks outside the default policy"
OUTSIDE_NOTES = (
    "These attacks target channels the default policy leaves open. High success rates here "
    "are expected and show where it fails; they are not a regression.",
    "exfil_get leaks through a web.fetch URL (the policy linter reports web.fetch as having "
    "no rule). exfil_internal leaks data labeled internal, which the default threshold allows. "
    "exfil_mislabeled leaks data carrying a wrong public label. answer_poison changes what "
    "the user is told without any tool call.",
    "taintwatch-strict tightens confidentiality thresholds and covers web.*. It has no rule "
    "about where data is sent, so it cannot stop mislabeled data, and nothing in this policy "
    "language constrains the final answer.",
    "Benign utility is measured on the main benign tasks.",
    "An observed 0% is not a zero rate. Read the upper end of the interval.",
)


def _approve(tool: str, verdict: Verdict) -> bool:
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taintwatch.evaluation.outside",
        description="Evaluate defenses on attacks outside the guarded sinks.",
    )
    parser.add_argument("--attacks", type=int, default=200)
    parser.add_argument("--benign", type=int, default=200)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--repeats", type=int, default=1, help="timing repeats per run")
    parser.add_argument("--confirm", action="store_true", help="auto-approve confirm verdicts")
    parser.add_argument("--defenses", nargs="+", default=list(OUTSIDE_SPECS))
    parser.add_argument("--out", default="results/outside")
    args = parser.parse_args(argv)
    confirm: ConfirmFn | None = _approve if args.confirm else None
    try:
        attacks = generate_outside_attacks(args.attacks, args.seed)
        benign = generate_benign(args.benign, args.seed)
        defenses = [build_defense(spec) for spec in args.defenses]
        records = evaluate(
            [*attacks, *benign], defenses, seed=args.seed, confirm=confirm, repeats=args.repeats
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out = Path(args.out)
    write_csv(records, out / "records.csv")
    markdown = render_markdown(records, summarize(records), title=TITLE, notes=OUTSIDE_NOTES)
    (out / "report.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"wrote {len(records)} runs to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
