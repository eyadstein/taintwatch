import random
from collections import Counter
from pathlib import Path

import pytest

from taintwatch.bench import (
    FAMILIES,
    GOALS,
    GRID_SIZE,
    Scenario,
    build_suite,
    generate_attacks,
    generate_benign,
    grid,
    read_jsonl,
    write_jsonl,
)
from taintwatch.bench.__main__ import main
from taintwatch.bench.content import INERT_WARNINGS, SENTENCES, carry, make_text


def carrier_text(scenario: Scenario) -> str:
    if scenario.web:
        return scenario.web[0][1]
    if scenario.inbox:
        return scenario.inbox[0]
    return scenario.files[0][1].content


def test_text_pools_are_clean() -> None:
    for sentence in (*SENTENCES, *INERT_WARNINGS):
        assert len(sentence) >= 30
        assert not any(ch in sentence for ch in '"{}<>')
    assert len(set(SENTENCES)) == len(SENTENCES)


def test_make_text_has_distinct_sentences() -> None:
    text = make_text(random.Random(1))
    assert text.count(".") == 3


def test_carry_rejects_unknown_carrier() -> None:
    with pytest.raises(ValueError):
        carry("fax", "x", random.Random(1))


def test_grid_size() -> None:
    assert GRID_SIZE == 1080
    assert len(grid()) == GRID_SIZE


def test_default_attacks_are_balanced() -> None:
    attacks = generate_attacks()
    assert len(attacks) == 600
    assert Counter(s.family for s in attacks) == {f"attack/{g}": 120 for g in GOALS}
    assert len({s.id for s in attacks}) == 600


def test_full_grid_has_no_duplicates() -> None:
    attacks = generate_attacks(GRID_SIZE)
    assert len(attacks) == GRID_SIZE
    assert len({s.meta for s in attacks}) == GRID_SIZE


def test_attack_count_bounds() -> None:
    with pytest.raises(ValueError):
        generate_attacks(GRID_SIZE + 1)
    with pytest.raises(ValueError):
        generate_attacks(-1)
    assert generate_attacks(0) == []


def test_generation_is_deterministic_and_seeded() -> None:
    assert generate_attacks(50, seed=3) == generate_attacks(50, seed=3)
    assert generate_attacks(50, seed=3) != generate_attacks(50, seed=4)
    assert generate_benign(30, seed=3) == generate_benign(30, seed=3)


def test_every_attack_carries_a_directive() -> None:
    for scenario in generate_attacks(GRID_SIZE):
        assert "<<call " in carrier_text(scenario)
        assert scenario.attack is not None
        assert scenario.utility is not None


def test_exfil_scenarios_read_the_secret_first() -> None:
    for scenario in generate_attacks(300):
        first = scenario.plan[0]
        reads_secret = first.tool == "fs.read" and first.args.get("path") == "/secrets/key.txt"
        assert reads_secret == scenario.family.startswith("attack/exfil")


def test_benign_covers_every_family() -> None:
    benign = generate_benign(200)
    assert len(benign) == 200
    counts = Counter(s.family for s in benign)
    assert set(counts) == {f"benign/{f}" for f in FAMILIES}
    assert min(counts.values()) >= 28
    assert all("<<call" not in carrier_text(s) for s in benign if s.web or s.inbox or s.files)
    assert all(s.attack is None and s.utility is not None for s in benign)


def test_benign_negative_count() -> None:
    with pytest.raises(ValueError):
        generate_benign(-1)


def test_suite_counts_and_scenarios() -> None:
    suite = build_suite(40, 14)
    assert len(suite.attacks) == 40
    assert len(suite.benign) == 14
    assert len(suite.scenarios) == 54
    assert sum(suite.counts().values()) == 54


def test_jsonl_roundtrip(tmp_path: Path) -> None:
    suite = build_suite(25, 14)
    target = tmp_path / "out" / "s.jsonl"
    assert write_jsonl(suite.scenarios, target) == 39
    assert read_jsonl(target) == list(suite.scenarios)


def test_cli_writes_a_dataset(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "s.jsonl"
    code = main(["--attacks", "10", "--benign", "7", "--out", str(target)])
    assert code == 0
    assert len(target.read_text(encoding="utf-8").splitlines()) == 17
    assert "wrote 17 scenarios" in capsys.readouterr().out


def test_cli_rejects_impossible_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--attacks", "5000", "--out", str(tmp_path / "x.jsonl")]) == 1
    assert "error" in capsys.readouterr().err
