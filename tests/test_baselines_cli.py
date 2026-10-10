import pytest

from taintwatch.baselines.__main__ import main


def test_cli_prints_a_comparison_table(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--attacks", "10", "--benign", "7", "--defenses", "none", "taintwatch"])
    out = capsys.readouterr().out
    assert code == 0
    assert "attack success" in out
    assert "none" in out
    assert "taintwatch" in out
    assert "10 attacks, 7 benign tasks" in out


def test_cli_accepts_parameterized_specs(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--attacks", "5", "--benign", "7", "--defenses", "scorer@1.5", "spotlight@0.5"])
    out = capsys.readouterr().out
    assert code == 0
    assert "scorer@1.5" in out
    assert "spotlight@0.5" in out


def test_cli_rejects_unknown_defenses(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--attacks", "5", "--benign", "7", "--defenses", "bogus"]) == 1
    assert "error" in capsys.readouterr().err


def test_cli_rejects_bad_parameters(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--attacks", "5", "--benign", "7", "--defenses", "scorer@x"]) == 1
    assert "error" in capsys.readouterr().err
