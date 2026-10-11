import ast
import importlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from taintwatch.analysis import build_notebooks, read_points_csv
from taintwatch.analysis.__main__ import main

COMMITTED = Path(__file__).resolve().parents[1] / "notebooks"


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def code_sources(notebook: dict[str, Any]) -> list[str]:
    return ["".join(c["source"]) for c in notebook["cells"] if c["cell_type"] == "code"]


def taintwatch_imports(source: str) -> Iterator[tuple[str, list[str]]]:
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        if node.module.startswith("taintwatch"):
            yield node.module, [alias.name for alias in node.names]


def test_notebooks_are_valid(tmp_path: Path) -> None:
    paths = build_notebooks(tmp_path / "nb")
    assert [p.name for p in paths] == ["01_report.ipynb", "02_ablation_and_sweeps.ipynb"]
    for path in paths:
        notebook = load(path)
        assert (notebook["nbformat"], notebook["nbformat_minor"]) == (4, 5)
        ids = [cell["id"] for cell in notebook["cells"]]
        assert len(set(ids)) == len(ids)
        assert len(code_sources(notebook)) >= 4
        for cell in notebook["cells"]:
            if cell["cell_type"] == "code":
                assert cell["outputs"] == []
                assert cell["execution_count"] is None


def test_every_code_cell_parses_and_every_import_resolves(tmp_path: Path) -> None:
    for path in build_notebooks(tmp_path / "nb"):
        for source in code_sources(load(path)):
            for module, names in taintwatch_imports(source):
                imported = importlib.import_module(module)
                for name in names:
                    assert hasattr(imported, name), f"{module}.{name} in {path.name}"


def test_generation_is_deterministic(tmp_path: Path) -> None:
    first = build_notebooks(tmp_path / "a")
    second = build_notebooks(tmp_path / "b")
    for one, two in zip(first, second, strict=True):
        assert one.read_bytes() == two.read_bytes()


def test_committed_notebooks_match_the_generator(tmp_path: Path) -> None:
    for fresh in build_notebooks(tmp_path / "fresh"):
        committed = COMMITTED / fresh.name
        assert committed.exists(), f"missing {committed}"
        assert committed.read_text(encoding="utf-8") == fresh.read_text(encoding="utf-8")


def test_cli_notebooks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["notebooks", "--out", str(tmp_path / "nb")]) == 0
    assert (tmp_path / "nb" / "01_report.ipynb").exists()
    assert "wrote" in capsys.readouterr().out


def test_cli_sweeps(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "s.csv"
    code = main(["sweeps", "--attacks", "10", "--benign", "7", "--out", str(target)])
    assert code == 0
    assert len(read_points_csv(target)) == 4 + 10 + 7
    assert "wrote 21 points" in capsys.readouterr().out


def test_cli_rejects_impossible_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["sweeps", "--attacks", "5000", "--out", str(tmp_path / "x.csv")]) == 1
    assert "error" in capsys.readouterr().err
