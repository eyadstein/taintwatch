import pytest

from taintwatch.baselines import build_defense
from taintwatch.bench import GOALS, Suite, build_suite
from taintwatch.evaluation import RunRecord, evaluate


@pytest.fixture(scope="module")
def suite() -> Suite:
    return build_suite(30, 14)


def outcomes(records: list[RunRecord]) -> list[tuple[object, ...]]:
    return [
        (r.defense, r.scenario_id, r.attack_succeeded, r.utility_ok, r.blocked, r.calls, r.steps)
        for r in records
    ]


def run(suite: Suite, *specs: str, repeats: int = 1) -> list[RunRecord]:
    defenses = [build_defense(spec) for spec in specs]
    return evaluate(suite.scenarios, defenses, repeats=repeats)


def test_one_record_per_defense_and_scenario(suite: Suite) -> None:
    records = run(suite, "none", "taintwatch")
    assert len(records) == 2 * len(suite.scenarios)
    assert {r.defense for r in records[: len(suite.scenarios)]} == {"none"}
    assert [r.scenario_id for r in records[: len(suite.scenarios)]] == [
        s.id for s in suite.scenarios
    ]


def test_outcomes_match_the_known_defense_behavior(suite: Suite) -> None:
    records = run(suite, "none", "taintwatch")
    none_attacks = [r for r in records if r.defense == "none" and r.is_attack]
    tw_attacks = [r for r in records if r.defense == "taintwatch" and r.is_attack]
    assert len(none_attacks) == 30
    assert all(r.attack_succeeded for r in none_attacks)
    assert not any(r.attack_succeeded for r in tw_attacks)
    assert all(r.blocked >= 1 for r in tw_attacks)
    assert all(r.blocked == 0 for r in none_attacks)


def test_records_carry_tags_and_timing(suite: Suite) -> None:
    records = run(suite, "none")
    attacks = [r for r in records if r.is_attack]
    benign = [r for r in records if not r.is_attack]
    assert all(r.tag("goal") in GOALS for r in attacks)
    assert all(r.tag("family") for r in benign)
    assert all(r.tag("goal") == "" for r in benign)
    assert r_tag_default(benign[0]) == "?"
    assert all(r.latency_ms > 0 for r in records)
    assert all(r.steps >= 1 for r in records)


def r_tag_default(record: RunRecord) -> str:
    return record.tag("nope", "?")


def test_outcomes_are_deterministic_across_runs(suite: Suite) -> None:
    first = run(suite, "none", "taintwatch", "spotlight@0.5")
    second = run(suite, "none", "taintwatch", "spotlight@0.5", repeats=2)
    assert outcomes(first) == outcomes(second)


def test_repeats_must_be_positive(suite: Suite) -> None:
    with pytest.raises(ValueError):
        run(suite, "none", repeats=0)
