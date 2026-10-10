import json
from pathlib import Path

import pytest

from taintwatch.baselines import build_defense
from taintwatch.bench import build_suite
from taintwatch.evaluation import (
    RunRecord,
    evaluate,
    read_records,
    render_markdown,
    summarize,
    write_csv,
    write_json,
)
from taintwatch.evaluation.__main__ import main


@pytest.fixture(scope="module")
def records() -> list[RunRecord]:
    suite = build_suite(20, 14)
    defenses = [build_defense("none"), build_defense("taintwatch")]
    return evaluate(suite.scenarios, defenses)


def test_csv_roundtrip(records: list[RunRecord], tmp_path: Path) -> None:
    target = tmp_path / "nested" / "records.csv"
    assert write_csv(records, target) == len(records)
    loaded = read_records(target)
    assert len(loaded) == len(records)
    for original, restored in zip(records, loaded, strict=True):
        assert restored.latency_ms == pytest.approx(original.latency_ms, abs=1e-4)
        assert restored.defense == original.defense
        assert restored.scenario_id == original.scenario_id
        assert restored.family == original.family
        assert restored.is_attack == original.is_attack
        assert restored.attack_succeeded == original.attack_succeeded
        assert restored.utility_ok == original.utility_ok
        assert (restored.blocked, restored.calls, restored.steps) == (
            original.blocked,
            original.calls,
            original.steps,
        )
        assert restored.tags == original.tags


def test_json_summary(records: list[RunRecord], tmp_path: Path) -> None:
    target = tmp_path / "summary.json"
    write_json(target, {"seed": 7}, summarize(records), [])
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["config"] == {"seed": 7}
    assert [d["defense"] for d in data["defenses"]] == ["none", "taintwatch"]
    assert data["defenses"][0]["attack_success"]["hits"] == 20
    assert data["defenses"][1]["attack_success"]["hits"] == 0
    assert data["paired_vs_taintwatch"] == []


def test_markdown_report(records: list[RunRecord]) -> None:
    text = render_markdown(records, summarize(records))
    assert text.isascii()
    for heading in (
        "## Overall",
        "## Attack success by goal",
        "## Attack success by carrier",
        "## Attack success by style",
        "## Benign utility by family",
        "## Paired comparison against taintwatch",
        "## Notes",
    ):
        assert heading in text
    assert "| none |" in text
    assert "| taintwatch |" in text
    assert "20 attacks and 14 benign tasks per defense" in text


def test_markdown_without_a_pivot_has_no_paired_section(records: list[RunRecord]) -> None:
    only_none = [r for r in records if r.defense == "none"]
    text = render_markdown(only_none, summarize(only_none))
    assert "Paired comparison" not in text


def test_cli_writes_all_outputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "r"
    code = main(
        [
            "--attacks", "10",
            "--benign", "7",
            "--defenses", "none", "taintwatch",
            "--repeats", "1",
            "--out", str(out),
        ]
    )
    assert code == 0
    assert (out / "records.csv").exists()
    assert (out / "summary.json").exists()
    assert (out / "report.md").exists()
    printed = capsys.readouterr().out
    assert "## Overall" in printed
    assert "wrote 34 runs" in printed


def test_cli_rejects_bad_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = ["--attacks", "5", "--benign", "7", "--out", str(tmp_path / "x")]
    assert main([*base, "--defenses", "bogus"]) == 1
    assert main([*base, "--defenses", "none", "--repeats", "0"]) == 1
    assert "error" in capsys.readouterr().err
