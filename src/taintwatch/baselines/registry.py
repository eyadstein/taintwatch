"""Named defenses and the parser for specs such as ``scorer@1.5``."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from taintwatch.baselines.defense import Defense
from taintwatch.baselines.keyword import DEFAULT_PHRASES, KeywordFilter
from taintwatch.baselines.scorer import HeuristicScorer
from taintwatch.baselines.wrappers import (
    context_taint_wrapper,
    detector_wrapper,
    spotlight_wrapper,
)
from taintwatch.policy import Policy, default_policy

DEFAULT_SPECS = ("none", "taintwatch", "taintwatch-coarse", "keyword", "scorer", "spotlight")


def no_defense() -> Defense:
    return Defense("none", "No protection.", Policy())


def taintwatch_defense() -> Defense:
    return Defense(
        "taintwatch",
        "Span-level information-flow control with the default policy.",
        default_policy(),
    )


def coarse_defense() -> Defense:
    return Defense(
        "taintwatch-coarse",
        "Ablation: default policy, but calls carry the taint of the whole context.",
        default_policy(),
        context_taint_wrapper,
    )


def keyword_defense(phrases: Sequence[str] = DEFAULT_PHRASES) -> Defense:
    return Defense(
        "keyword",
        "Removes tool output that contains a suspicious phrase.",
        Policy(),
        detector_wrapper(KeywordFilter(phrases).flags),
    )


def scorer_defense(threshold: float = 2.5) -> Defense:
    scorer = HeuristicScorer(threshold=threshold)
    return Defense(
        f"scorer@{threshold:g}",
        "Removes tool output whose heuristic injection score reaches the threshold.",
        Policy(),
        detector_wrapper(scorer.flags),
    )


def spotlight_defense(resist: float = 0.9) -> Defense:
    if not 0.0 <= resist <= 1.0:
        raise ValueError("resist must be between 0 and 1")
    return Defense(
        f"spotlight@{resist:g}",
        "Models spotlighting: untrusted output is treated as data with probability resist.",
        Policy(),
        spotlight_wrapper(resist),
    )


_SIMPLE: dict[str, Callable[[], Defense]] = {
    "none": no_defense,
    "taintwatch": taintwatch_defense,
    "taintwatch-coarse": coarse_defense,
    "keyword": keyword_defense,
}
_PARAMETRIC: dict[str, tuple[Callable[[float], Defense], float]] = {
    "scorer": (scorer_defense, 2.5),
    "spotlight": (spotlight_defense, 0.9),
}


def build_defense(spec: str) -> Defense:
    """Build a defense from a spec like ``taintwatch``, ``scorer@1.5`` or ``spotlight@0.5``."""
    name, has_arg, arg = spec.partition("@")
    simple = _SIMPLE.get(name)
    if simple is not None:
        if has_arg:
            raise ValueError(f"defense {name!r} takes no parameter")
        return simple()
    parametric = _PARAMETRIC.get(name)
    if parametric is None:
        known = ", ".join(sorted((*_SIMPLE, *_PARAMETRIC)))
        raise ValueError(f"unknown defense {spec!r}; known: {known}")
    factory, default = parametric
    if not has_arg:
        return factory(default)
    try:
        value = float(arg)
    except ValueError:
        raise ValueError(f"invalid parameter {arg!r} for defense {name!r}") from None
    return factory(value)
