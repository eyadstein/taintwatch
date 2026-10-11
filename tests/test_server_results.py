from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from taintwatch.baselines import build_defense
from taintwatch.bench import FAMILIES, GOALS, build_suite
from taintwatch.evaluation import evaluate, write_csv
from taintwatch.server import create_app
from taintwatch.server.results import load_results


@pytest.fixture(scope="module")
def results_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    suite = build_suite(20, 14)
    defenses = [build_defense("none"), build_defense("taintwatch")]
    directory = tmp_path_factory.mktemp("results")
    write_csv(evaluate(suite.scenarios, defenses), directory / "records.csv")
    return directory


def make_client(directory: Path) -> TestClient:
    app = create_app(":memory:", suite=build_suite(2, 7), results_dir=str(directory))
    return TestClient(app)


def test_missing_results_directory_gives_none(tmp_path: Path) -> None:
    assert load_results(tmp_path) is None


def test_endpoint_is_a_404_with_a_hint_when_nothing_was_evaluated(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/results")
    assert response.status_code == 404
    assert "taintwatch.evaluation" in response.json()["detail"]


def test_summary_rates(results_dir: Path) -> None:
    data = make_client(results_dir).get("/api/results").json()
    assert data["pivot"] == "taintwatch"
    assert [d["defense"] for d in data["defenses"]] == ["none", "taintwatch"]
    none, taintwatch = data["defenses"]
    assert (none["attack_success"]["hits"], none["attack_success"]["total"]) == (20, 20)
    assert taintwatch["attack_success"]["hits"] == 0
    assert taintwatch["benign_utility"]["total"] == 14
    assert taintwatch["benign_utility"]["hits"] == 12
    assert none["overhead"] == pytest.approx(1.0)


def test_attack_breakdowns(results_dir: Path) -> None:
    data = make_client(results_dir).get("/api/results").json()
    assert set(data["attack_breakdown"]) == {"goal", "carrier", "style"}
    goals = data["attack_breakdown"]["goal"]["none"]
    assert set(goals) == set(GOALS)
    assert all(rate["total"] == 4 and rate["hits"] == 4 for rate in goals.values())
    carriers = set(data["attack_breakdown"]["carrier"]["taintwatch"])
    assert carriers and carriers <= {"web", "email", "file"}


def test_benign_breakdown(results_dir: Path) -> None:
    data = make_client(results_dir).get("/api/results").json()
    families = data["benign_breakdown"]["taintwatch"]
    assert set(families) == {f"benign/{family}" for family in FAMILIES}
    assert families["benign/save_notes"]["hits"] == 0
    assert families["benign/save_notes"]["total"] == 2
    assert data["benign_breakdown"]["none"]["benign/save_notes"]["hits"] == 2


def test_paired_comparison(results_dir: Path) -> None:
    data = make_client(results_dir).get("/api/results").json()
    (paired,) = data["paired"]
    assert paired["defense"] == "none"
    assert paired["pivot"] == "taintwatch"
    assert paired["only_defense_succeeds"] == 20
    assert paired["only_pivot_succeeds"] == 0
    assert paired["mcnemar_p"] < 1e-5
