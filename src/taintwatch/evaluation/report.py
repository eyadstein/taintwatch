"""Write evaluation results as CSV, JSON and a Markdown report. Output is plain ASCII."""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from taintwatch.evaluation.metrics import (
    DefenseSummary,
    PairedResult,
    attack_breakdown,
    benign_breakdown,
    compare_to_pivot,
)
from taintwatch.evaluation.runner import RunRecord
from taintwatch.evaluation.stats import Rate

PIVOT = "taintwatch"
FIELDS = (
    "defense",
    "scenario_id",
    "family",
    "is_attack",
    "attack_succeeded",
    "utility_ok",
    "blocked",
    "calls",
    "steps",
    "latency_ms",
    "tags",
)
OVERALL_HEADERS = (
    "defense",
    "attack success (95% CI)",
    "benign utility",
    "utility under attack",
    "benign policy blocks",
    "median ms",
    "p95 ms",
    "overhead",
)
NOTES = (
    "Latency is wall-clock time of the mock run (agent, guard and tools, no model). "
    "It shows relative guard cost only; real model latency would dominate.",
    "An observed 0% is not a zero rate. Read the upper end of the interval.",
    "Benign policy blocks counts guard blocks only. Filter-style defenses act before the "
    "runtime and show up as lost utility instead.",
    "Spotlight rows depend on an assumed resistance probability, not a measurement.",
    "Attack goals match the sinks the default policy guards, so the taintwatch result is "
    "partly by construction.",
)


def _format_tags(tags: tuple[tuple[str, str], ...]) -> str:
    return ";".join(f"{key}={value}" for key, value in tags)


def _parse_tags(text: str) -> tuple[tuple[str, str], ...]:
    if not text:
        return ()
    pairs = (item.partition("=") for item in text.split(";"))
    return tuple((key, value) for key, _, value in pairs)


def write_csv(records: Sequence[RunRecord], path: str | Path) -> int:
    """Write one row per run. Returns the number of rows."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    "defense": record.defense,
                    "scenario_id": record.scenario_id,
                    "family": record.family,
                    "is_attack": int(record.is_attack),
                    "attack_succeeded": int(record.attack_succeeded),
                    "utility_ok": int(record.utility_ok),
                    "blocked": record.blocked,
                    "calls": record.calls,
                    "steps": record.steps,
                    "latency_ms": f"{record.latency_ms:.4f}",
                    "tags": _format_tags(record.tags),
                }
            )
    return len(records)


def _parse_row(row: Mapping[str, str]) -> RunRecord:
    return RunRecord(
        defense=row["defense"],
        scenario_id=row["scenario_id"],
        family=row["family"],
        is_attack=row["is_attack"] == "1",
        attack_succeeded=row["attack_succeeded"] == "1",
        utility_ok=row["utility_ok"] == "1",
        blocked=int(row["blocked"]),
        calls=int(row["calls"]),
        steps=int(row["steps"]),
        latency_ms=float(row["latency_ms"]),
        tags=_parse_tags(row["tags"]),
    )


def read_records(path: str | Path) -> list[RunRecord]:
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return [_parse_row(row) for row in csv.DictReader(handle)]


def summary_to_dict(summary: DefenseSummary) -> dict[str, object]:
    return {
        "defense": summary.defense,
        "attack_success": summary.attack_success.to_dict(),
        "utility_under_attack": summary.utility_under_attack.to_dict(),
        "benign_utility": summary.benign_utility.to_dict(),
        "benign_blocked": summary.benign_blocked.to_dict(),
        "latency_median_ms": summary.latency_median_ms,
        "latency_p95_ms": summary.latency_p95_ms,
        "overhead": summary.overhead,
    }


def comparison_to_dict(result: PairedResult) -> dict[str, object]:
    return {
        "defense": result.a,
        "pivot": result.b,
        "only_defense_succeeds": result.only_a,
        "only_pivot_succeeds": result.only_b,
        "mcnemar_p": result.p_value,
    }


def write_json(
    path: str | Path,
    config: Mapping[str, object],
    summaries: Sequence[DefenseSummary],
    comparisons: Sequence[PairedResult],
) -> None:
    payload = {
        "config": dict(config),
        "defenses": [summary_to_dict(s) for s in summaries],
        "paired_vs_taintwatch": [comparison_to_dict(c) for c in comparisons],
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def _overhead(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}x"


def _p_value(value: float) -> str:
    return f"{value:.2e}" if value < 0.001 else f"{value:.3f}"


def _overall_row(summary: DefenseSummary) -> list[str]:
    return [
        summary.defense,
        summary.attack_success.fmt(),
        summary.benign_utility.percent(),
        summary.utility_under_attack.percent(),
        summary.benign_blocked.percent(),
        f"{summary.latency_median_ms:.3f}",
        f"{summary.latency_p95_ms:.3f}",
        _overhead(summary.overhead),
    ]


def _attack_matrix(records: Sequence[RunRecord], names: Sequence[str], key: str) -> str:
    columns = sorted({r.tag(key, "?") for r in records if r.is_attack})
    if not columns:
        return "No attack scenarios."
    rows: list[list[str]] = []
    for name in names:
        rates: dict[str, Rate] = attack_breakdown(records, name, key)
        rows.append([name, *(rates[c].percent() if c in rates else "n/a" for c in columns)])
    return _table(["defense", *columns], rows)


def _benign_matrix(records: Sequence[RunRecord], names: Sequence[str]) -> str:
    columns = sorted({r.family for r in records if not r.is_attack})
    if not columns:
        return "No benign scenarios."
    rows: list[list[str]] = []
    for name in names:
        rates = benign_breakdown(records, name)
        rows.append([name, *(rates[c].percent() if c in rates else "n/a" for c in columns)])
    return _table(["defense", *columns], rows)


def render_markdown(
    records: Sequence[RunRecord],
    summaries: Sequence[DefenseSummary],
    pivot: str = PIVOT,
    *,
    title: str = "Taintwatch benchmark results",
    notes: Sequence[str] = NOTES,
) -> str:
    names = [s.defense for s in summaries]
    parts = [f"# {title}", ""]
    if summaries:
        first = summaries[0]
        parts.append(
            f"{first.attack_success.total} attacks and {first.benign_utility.total} benign "
            "tasks per defense. Intervals are 95% Wilson score intervals."
        )
        parts.append("")
    parts += ["## Overall", "", _table(OVERALL_HEADERS, [_overall_row(s) for s in summaries])]
    for key in ("goal", "carrier", "style"):
        parts += ["", f"## Attack success by {key}", "", _attack_matrix(records, names, key)]
    parts += ["", "## Benign utility by family", "", _benign_matrix(records, names)]
    comparisons = compare_to_pivot(records, names, pivot)
    if comparisons:
        rows = [
            [c.a, str(c.only_a), str(c.only_b), _p_value(c.p_value)] for c in comparisons
        ]
        headers = [
            "defense",
            "attacks that succeed only against it",
            f"attacks that succeed only against {pivot}",
            "exact McNemar p",
        ]
        parts += ["", f"## Paired comparison against {pivot}", "", _table(headers, rows)]
    parts += ["", "## Notes", ""]
    parts += [f"- {note}" for note in notes]
    return "\n".join(parts) + "\n"
