"""Generate the analysis notebooks as plain JSON, so they diff cleanly and need no extra tools."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Cell:
    kind: str
    source: str


def md(text: str) -> Cell:
    return Cell("markdown", text.strip("\n"))


def code(text: str) -> Cell:
    return Cell("code", text.strip("\n"))


def _cell_json(cell: Cell, index: int) -> dict[str, object]:
    data: dict[str, object] = {
        "cell_type": cell.kind,
        "id": f"cell-{index:02d}",
        "metadata": {},
        "source": cell.source.splitlines(keepends=True),
    }
    if cell.kind == "code":
        data["execution_count"] = None
        data["outputs"] = []
    return data


def render(cells: Sequence[Cell]) -> str:
    notebook = {
        "cells": [_cell_json(cell, i) for i, cell in enumerate(cells, start=1)],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return json.dumps(notebook, indent=1) + "\n"


REPORT = (
    md("""
# Taintwatch benchmark report

Reproduces the tables in `results/report.md` from `results/records.csv`.
Generate that file first with `python -m taintwatch.evaluation`.
Intervals are 95% Wilson score intervals.
"""),
    code("""
from pathlib import Path

import matplotlib.pyplot as plt

from taintwatch.evaluation import (
    attack_breakdown,
    benign_breakdown,
    compare_to_pivot,
    read_records,
    summarize,
)

ROOT = Path.cwd()
if not (ROOT / 'results').exists():
    ROOT = ROOT.parent
records = read_records(ROOT / 'results' / 'records.csv')
summaries = summarize(records)
names = [s.defense for s in summaries]
print(len(records), 'runs;', ', '.join(names))
"""),
    md("## Overall"),
    code("""
print(f"{'defense':<20}{'attack success (95% CI)':<30}{'benign utility':>16}")
for s in summaries:
    print(f'{s.defense:<20}{s.attack_success.fmt():<30}{s.benign_utility.percent():>16}')
"""),
    code("""
def bars(title, rates, color):
    labels = [name for name, _ in rates]
    values = [r.value * 100 for _, r in rates]
    low = [max(0.0, (r.value - r.interval()[0]) * 100) for _, r in rates]
    high = [max(0.0, (r.interval()[1] - r.value) * 100) for _, r in rates]
    fig, ax = plt.subplots(figsize=(8, 0.5 * len(labels) + 1.5))
    ax.barh(labels, values, xerr=[low, high], color=color, capsize=3)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel('percent')
    ax.set_title(title)
    fig.tight_layout()
    plt.show()


bars('Attack success (lower is better)',
     [(s.defense, s.attack_success) for s in summaries], '#8a2a1b')
bars('Benign utility (higher is better)',
     [(s.defense, s.benign_utility) for s in summaries], '#1f5c4d')
"""),
    md("""
An observed 0% is not a zero rate: with 600 attacks the upper end of the interval is about 0.6%.
The attack goals match the sinks the default policy guards, so the taintwatch result is partly
by construction.
"""),
    md("## Breakdowns"),
    code("""
for key in ('goal', 'carrier', 'style'):
    print('Attack success by', key)
    for name in names:
        groups = attack_breakdown(records, name, key)
        cells = ', '.join(f'{k}={r.percent()}' for k, r in groups.items())
        print(f'  {name:<20}{cells}')
    print()
"""),
    code("""
print('Benign utility by family')
for name in names:
    groups = benign_breakdown(records, name)
    cells = ', '.join(f'{k.split("/")[-1]}={r.percent()}' for k, r in groups.items())
    print(f'  {name:<20}{cells}')
"""),
    md("## Paired comparison against taintwatch"),
    code("""
for p in compare_to_pivot(records, names, 'taintwatch'):
    print(f'{p.a:<20} only-it {p.only_a:>4}  only-taintwatch {p.only_b:>4}  p={p.p_value:.2e}')
"""),
)

SWEEPS = (
    md("""
# Ablation and sensitivity sweeps

Needs `results/records.csv` (`python -m taintwatch.evaluation`) and `results/sweeps.csv`
(`python -m taintwatch.analysis sweeps`).

Spotlight rows depend on an assumed resistance probability, and the scorer weights are
hand-written, so read the curves as properties of these baselines and not of detectors in general.
"""),
    code("""
from pathlib import Path

import matplotlib.pyplot as plt

from taintwatch.analysis import pareto_front, read_points_csv
from taintwatch.evaluation import benign_breakdown, read_records

ROOT = Path.cwd()
if not (ROOT / 'results').exists():
    ROOT = ROOT.parent
points = read_points_csv(ROOT / 'results' / 'sweeps.csv')
scorer = sorted((p for p in points if p.defense.startswith('scorer@')), key=lambda p: p.param or 0)
spotlight = sorted(
    (p for p in points if p.defense.startswith('spotlight@')), key=lambda p: p.param or 0
)
refs = [p for p in points if p.param is None]
print(len(points), 'points:', len(scorer), 'scorer,', len(spotlight), 'spotlight,',
      len(refs), 'reference')
"""),
    md("## Attack success against benign utility (top left is best)"),
    code("""
def xy(items):
    return ([p.attack_success.value * 100 for p in items],
            [p.benign_utility.value * 100 for p in items])


fig, ax = plt.subplots(figsize=(7, 5))
ax.plot(*xy(scorer), marker='o', label='scorer (threshold sweep)')
for p in scorer:
    ax.annotate(f'{p.param:g}', (p.attack_success.value * 100, p.benign_utility.value * 100),
                textcoords='offset points', xytext=(4, 4), fontsize=8)
ax.plot(*xy(spotlight), marker='s', label='spotlight (resistance sweep)')
for p in refs:
    x, y = xy([p])
    ax.scatter(x, y, marker='*', s=140, label=p.defense)
ax.set_xlabel('attack success (%), lower is better')
ax.set_ylabel('benign utility (%), higher is better')
ax.legend(fontsize=8)
fig.tight_layout()
plt.show()
"""),
    md("## Spotlight sensitivity"),
    code("""
xs = [p.param for p in spotlight]
ys = [p.attack_success.value * 100 for p in spotlight]
rates = [p.attack_success for p in spotlight]
low = [max(0.0, (r.value - r.interval()[0]) * 100) for r in rates]
high = [max(0.0, (r.interval()[1] - r.value) * 100) for r in rates]
fig, ax = plt.subplots(figsize=(6, 3.5))
ax.errorbar(xs, ys, yerr=[low, high], marker='o', capsize=3)
ax.set_xlabel('assumed resistance probability')
ax.set_ylabel('attack success (%)')
fig.tight_layout()
plt.show()
"""),
    md("## Pareto front"),
    code("""
for p in pareto_front(points):
    attack, benign = p.attack_success.percent(), p.benign_utility.percent()
    print(f'{p.defense:<20} attack {attack:>7}  benign {benign:>7}')
"""),
    md("""
## Ablation: span-level versus whole-context labels

Both defenses stop the same attacks. The difference is utility: labeling a call with the taint
of the whole context rejects tasks that only forward trusted values.
"""),
    code("""
records = read_records(ROOT / 'results' / 'records.csv')
span = benign_breakdown(records, 'taintwatch')
coarse = benign_breakdown(records, 'taintwatch-coarse')
print(f"{'family':<24}{'span-level':>12}{'whole-context':>16}")
for family in span:
    print(f'{family:<24}{span[family].percent():>12}{coarse[family].percent():>16}')
"""),
)

NOTEBOOKS: dict[str, tuple[Cell, ...]] = {
    "01_report.ipynb": REPORT,
    "02_ablation_and_sweeps.ipynb": SWEEPS,
}


def build_notebooks(directory: str | Path) -> list[Path]:
    """Write every notebook into ``directory`` and return the paths."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, cells in NOTEBOOKS.items():
        path = target / name
        path.write_bytes(render(cells).encode("utf-8"))
        written.append(path)
    return written
