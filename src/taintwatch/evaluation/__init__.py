"""Evaluation runner, metrics and reports."""

from __future__ import annotations

from taintwatch.evaluation.metrics import (
    DefenseSummary,
    PairedResult,
    attack_breakdown,
    benign_breakdown,
    compare_to_pivot,
    paired_attack_comparison,
    summarize,
)
from taintwatch.evaluation.report import (
    PIVOT,
    read_records,
    render_markdown,
    write_csv,
    write_json,
)
from taintwatch.evaluation.runner import RunRecord, evaluate
from taintwatch.evaluation.stats import Rate, mcnemar_exact, median, percentile, wilson_interval

__all__ = [
    "PIVOT",
    "DefenseSummary",
    "PairedResult",
    "Rate",
    "RunRecord",
    "attack_breakdown",
    "benign_breakdown",
    "compare_to_pivot",
    "evaluate",
    "mcnemar_exact",
    "median",
    "paired_attack_comparison",
    "percentile",
    "read_records",
    "render_markdown",
    "summarize",
    "wilson_interval",
    "write_csv",
    "write_json",
]
