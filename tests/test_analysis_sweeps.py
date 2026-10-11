from pathlib import Path

import pytest

from taintwatch.analysis import (
    SweepPoint,
    pareto_front,
    read_points_csv,
    run_specs,
    run_sweep,
    write_points_csv,
)
from taintwatch.bench import Scenario, build_suite
from taintwatch.evaluation import Rate
from taintwatch.policy import Verdict


def approve(tool: str, verdict: Verdict) -> bool:
    return True


@pytest.fixture(scope="module")
def scenarios() -> tuple[Scenario, ...]:
    return build_suite(30, 14).scenarios


def point(name: str, attack: int, benign: int) -> SweepPoint:
    return SweepPoint(name, None, Rate(attack, 10), Rate(benign, 10))


def test_reference_specs(scenarios: tuple[Scenario, ...]) -> None:
    none, taintwatch = run_specs(["none", "taintwatch"], scenarios)
    assert (none.defense, none.param) == ("none", None)
    assert (none.attack_success.hits, none.attack_success.total) == (30, 30)
    assert (none.benign_utility.hits, none.benign_utility.total) == (14, 14)
    assert taintwatch.attack_success.hits == 0
    assert taintwatch.benign_utility.hits == 12


def test_confirm_restores_taintwatch_utility(scenarios: tuple[Scenario, ...]) -> None:
    (taintwatch,) = run_specs(["taintwatch"], scenarios, confirm=approve)
    assert taintwatch.benign_utility.hits == 14


def test_span_level_beats_whole_context_on_utility_only(
    scenarios: tuple[Scenario, ...],
) -> None:
    span, coarse = run_specs(["taintwatch", "taintwatch-coarse"], scenarios, confirm=approve)
    # Auto-approving the confirm rule lets exactly the file_write attacks through.
    file_writes = sum(1 for s in scenarios if s.family == "attack/file_write")
    assert file_writes == 6
    assert span.attack_success.hits == coarse.attack_success.hits == file_writes
    assert span.benign_utility.hits == 14
    assert coarse.benign_utility.hits == 12


def test_scorer_sweep_is_monotone(scenarios: tuple[Scenario, ...]) -> None:
    points = run_sweep("scorer", [0.5, 2.5, 5.0], scenarios)
    assert [p.defense for p in points] == ["scorer@0.5", "scorer@2.5", "scorer@5"]
    assert [p.param for p in points] == [0.5, 2.5, 5.0]
    attacks = [p.attack_success.value for p in points]
    benign = [p.benign_utility.value for p in points]
    assert attacks == sorted(attacks)
    assert benign == sorted(benign)


def test_spotlight_sweep_endpoints(scenarios: tuple[Scenario, ...]) -> None:
    low, high = run_sweep("spotlight", [0.0, 1.0], scenarios)
    assert low.attack_success.hits == 30
    assert high.attack_success.hits == 0
    assert high.benign_utility.total == 14


def test_empty_scenarios_are_rejected() -> None:
    with pytest.raises(ValueError):
        run_specs(["none"], [])
    with pytest.raises(ValueError):
        run_sweep("scorer", [1.0], [])


def test_unknown_parameter_is_rejected(scenarios: tuple[Scenario, ...]) -> None:
    with pytest.raises(ValueError):
        run_sweep("scorer", [0.0], scenarios)


def test_pareto_front_drops_dominated_points() -> None:
    points = [point("a", 1, 9), point("b", 2, 8), point("c", 0, 5), point("d", 1, 9)]
    assert [p.defense for p in pareto_front(points)] == ["c", "a", "d"]
    assert pareto_front([]) == []


def test_csv_roundtrip(tmp_path: Path) -> None:
    points = [
        SweepPoint("scorer@2.5", 2.5, Rate(3, 30), Rate(10, 14)),
        point("none", 10, 10),
    ]
    target = tmp_path / "nested" / "sweeps.csv"
    assert write_points_csv(points, target) == 2
    assert read_points_csv(target) == points
