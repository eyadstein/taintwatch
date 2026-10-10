"""Baseline defenses to compare against Taintwatch."""

from __future__ import annotations

from taintwatch.baselines.defense import Defense, Wrapper
from taintwatch.baselines.keyword import DEFAULT_PHRASES, KeywordFilter
from taintwatch.baselines.registry import (
    DEFAULT_SPECS,
    build_defense,
    coarse_defense,
    keyword_defense,
    no_defense,
    scorer_defense,
    spotlight_defense,
    taintwatch_defense,
)
from taintwatch.baselines.run import run_defended
from taintwatch.baselines.scorer import DEFAULT_FEATURES, Feature, HeuristicScorer
from taintwatch.baselines.wrappers import ContextTaintAgent, ObservationFilterAgent

__all__ = [
    "DEFAULT_FEATURES",
    "DEFAULT_PHRASES",
    "DEFAULT_SPECS",
    "ContextTaintAgent",
    "Defense",
    "Feature",
    "HeuristicScorer",
    "KeywordFilter",
    "ObservationFilterAgent",
    "Wrapper",
    "build_defense",
    "coarse_defense",
    "keyword_defense",
    "no_defense",
    "run_defended",
    "scorer_defense",
    "spotlight_defense",
    "taintwatch_defense",
]
