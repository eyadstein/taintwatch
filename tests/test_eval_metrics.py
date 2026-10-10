import pytest

from taintwatch.evaluation import (
    Rate,
    RunRecord,
    attack_breakdown,
    benign_breakdown,
    compare_to_pivot,
    paired_attack_comparison,
    summarize,
)


def rec(
    defense: str,
    sid: str,
    *,
    attack: bool,
    succeeded: bool = False,
    utility: bool = True,
    blocked: int = 0,
    latency: float = 1.0,
    goal: str = "g1",
) -> RunRecord:
    tags = (("goal", goal),) if attack else ()
    family = "attack/x" if attack else "benign/y"
    return RunRecord(
        defense, sid, family, attack, succeeded, utility, blocked, 1, 2, latency, tags
    )


def sample() -> list[RunRecord]:
    rows = [rec("none", f"a{i}", attack=True, succeeded=True) for i in range(4)]
    rows += [rec("none", f"b{i}", attack=False) for i in range(2)]
    goals = ["g1", "g1", "g2", "g2"]
    for i, goal in enumerate(goals):
        rows.append(
            rec(
                "d",
                f"a{i}",
                attack=True,
                succeeded=i == 0,
                blocked=0 if i == 0 else 1,
                latency=2.0,
                goal=goal,
            )
        )
    rows.append(rec("d", "b0", attack=False, latency=2.0))
    rows.append(rec("d", "b1", attack=False, utility=False, blocked=1, latency=2.0))
    return rows


def test_summary_of_the_reference_defense() -> None:
    summary = summarize(sample())[0]
    assert summary.defense == "none"
    assert summary.attack_success == Rate(4, 4)
    assert summary.benign_utility == Rate(2, 2)
    assert summary.benign_blocked == Rate(0, 2)
    assert summary.overhead == pytest.approx(1.0)


def test_summary_of_another_defense() -> None:
    summary = summarize(sample())[1]
    assert summary.defense == "d"
    assert summary.attack_success == Rate(1, 4)
    assert summary.utility_under_attack == Rate(4, 4)
    assert summary.benign_utility == Rate(1, 2)
    assert summary.benign_blocked == Rate(1, 2)
    assert summary.latency_median_ms == pytest.approx(2.0)
    assert summary.latency_p95_ms == pytest.approx(2.0)
    assert summary.overhead == pytest.approx(2.0)


def test_overhead_needs_a_reference() -> None:
    summaries = summarize(sample(), reference="missing")
    assert all(s.overhead is None for s in summaries)


def test_attack_breakdown_by_tag() -> None:
    assert attack_breakdown(sample(), "d", "goal") == {"g1": Rate(1, 2), "g2": Rate(0, 2)}
    assert attack_breakdown(sample(), "d", "nope") == {"?": Rate(1, 4)}
    assert attack_breakdown(sample(), "missing", "goal") == {}


def test_benign_breakdown_by_family() -> None:
    assert benign_breakdown(sample(), "d") == {"benign/y": Rate(1, 2)}
    assert benign_breakdown(sample(), "none") == {"benign/y": Rate(2, 2)}


def test_paired_comparison() -> None:
    result = paired_attack_comparison(sample(), "none", "d")
    assert (result.only_a, result.only_b) == (3, 0)
    assert result.p_value == pytest.approx(0.25)
    reverse = paired_attack_comparison(sample(), "d", "none")
    assert (reverse.only_a, reverse.only_b) == (0, 3)


def test_compare_to_pivot() -> None:
    results = compare_to_pivot(sample(), ["none", "d"], "d")
    assert [(r.a, r.b) for r in results] == [("none", "d")]
    assert compare_to_pivot(sample(), ["none", "d"], "absent") == []
