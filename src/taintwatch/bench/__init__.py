"""Benchmark scenarios and the machinery to run them."""

from __future__ import annotations

from taintwatch.bench.attacks import (
    CARRIERS,
    GOALS,
    GRID_SIZE,
    STYLES,
    AttackSpec,
    generate_attacks,
    grid,
)
from taintwatch.bench.benign import FAMILIES, generate_benign
from taintwatch.bench.execute import Outcome, run_scenario
from taintwatch.bench.outside import OUTSIDE_GOALS, OUTSIDE_GRID_SIZE, generate_outside_attacks
from taintwatch.bench.scenario import Check, Effect, Scenario, make_meta
from taintwatch.bench.suite import Suite, build_suite, read_jsonl, write_jsonl

__all__ = [
    "CARRIERS",
    "FAMILIES",
    "GOALS",
    "GRID_SIZE",
    "OUTSIDE_GOALS",
    "OUTSIDE_GRID_SIZE",
    "STYLES",
    "AttackSpec",
    "Check",
    "Effect",
    "Outcome",
    "Scenario",
    "Suite",
    "build_suite",
    "generate_attacks",
    "generate_benign",
    "generate_outside_attacks",
    "grid",
    "make_meta",
    "read_jsonl",
    "run_scenario",
    "write_jsonl",
]
