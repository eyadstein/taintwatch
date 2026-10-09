from pathlib import Path

import pytest

from taintwatch.dsl.__main__ import main

DEFAULT_FILE = Path(__file__).resolve().parents[1] / "policies" / "default.twp"


def test_cli_accepts_default_policy() -> None:
    assert main([str(DEFAULT_FILE)]) == 0


def test_cli_usage_without_arguments() -> None:
    assert main([]) == 2


def test_cli_reports_syntax_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.twp"
    bad.write_text("rule", encoding="utf-8")
    assert main([str(bad)]) == 1
    assert "error" in capsys.readouterr().err


def test_cli_lists_warnings_without_failing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "p.twp"
    policy.write_text("rule r: block t when integrity < untrusted", encoding="utf-8")
    assert main([str(policy)]) == 0
    assert "never be true" in capsys.readouterr().out
