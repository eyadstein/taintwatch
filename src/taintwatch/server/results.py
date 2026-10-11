"""Evaluation results for the dashboard, computed from the stored run records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from taintwatch.evaluation import (
    PIVOT,
    attack_breakdown,
    benign_breakdown,
    compare_to_pivot,
    read_records,
    summarize,
)
from taintwatch.evaluation.report import comparison_to_dict, summary_to_dict

BREAKDOWN_KEYS = ("goal", "carrier", "style")


def load_results(directory: str | Path) -> dict[str, Any] | None:
    """Read ``records.csv`` from ``directory`` and compute every dashboard table.

    Returns ``None`` if the file does not exist.
    """
    path = Path(directory) / "records.csv"
    if not path.exists():
        return None
    records = read_records(path)
    summaries = summarize(records)
    names = [s.defense for s in summaries]
    attacks = {
        key: {
            name: {v: r.to_dict() for v, r in attack_breakdown(records, name, key).items()}
            for name in names
        }
        for key in BREAKDOWN_KEYS
    }
    benign = {
        name: {family: r.to_dict() for family, r in benign_breakdown(records, name).items()}
        for name in names
    }
    return {
        "pivot": PIVOT,
        "defenses": [summary_to_dict(s) for s in summaries],
        "attack_breakdown": attacks,
        "benign_breakdown": benign,
        "paired": [comparison_to_dict(c) for c in compare_to_pivot(records, names, PIVOT)],
    }
