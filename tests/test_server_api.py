import pytest
from fastapi.testclient import TestClient

from taintwatch.bench import Suite, build_suite
from taintwatch.server import TraceStore, create_app, record_run
from taintwatch.server.__main__ import build_parser


@pytest.fixture
def suite() -> Suite:
    return build_suite(20, 14)


@pytest.fixture
def client(suite: Suite) -> TestClient:
    return TestClient(create_app(":memory:", suite=suite))


def attack_id(suite: Suite) -> str:
    return suite.attacks[0].id


def confirm_id(suite: Suite) -> str:
    return next(s.id for s in suite.benign if s.meta_value("expects") == "confirm")


def test_health(client: TestClient) -> None:
    data = client.get("/api/health").json()
    assert data == {"status": "ok", "scenarios": 34, "runs": 0}


def test_defenses(client: TestClient) -> None:
    items = client.get("/api/defenses").json()
    assert [d["name"] for d in items] == [
        "none",
        "taintwatch",
        "taintwatch-coarse",
        "keyword",
        "scorer@2.5",
        "spotlight@0.9",
    ]
    assert all(d["description"] for d in items)


def test_scenario_listing_filters_and_pages(client: TestClient) -> None:
    everything = client.get("/api/scenarios").json()
    assert everything["total"] == 34
    attacks = client.get("/api/scenarios", params={"attack": "true"}).json()
    assert attacks["total"] == 20
    assert all(item["is_attack"] for item in attacks["items"])
    benign = client.get("/api/scenarios", params={"attack": "false"}).json()
    assert benign["total"] == 14
    family = client.get("/api/scenarios", params={"family": "benign/save_notes"}).json()
    assert family["total"] == 2
    page = client.get("/api/scenarios", params={"limit": 5, "offset": 3}).json()
    assert page["total"] == 34
    assert len(page["items"]) == 5
    assert page["items"][0]["id"] == everything["items"][3]["id"]


def test_scenario_detail(client: TestClient, suite: Suite) -> None:
    data = client.get(f"/api/scenarios/{attack_id(suite)}").json()
    assert data["id"] == attack_id(suite)
    assert data["attack"]["effect"]
    assert data["utility"]["effect"] == "answer_has"
    assert data["plan"]
    assert any("<<call " in page["text"] for page in data["web"]) or data["inbox"] or data["files"]


def test_unknown_scenario_and_run(client: TestClient) -> None:
    assert client.get("/api/scenarios/nope").status_code == 404
    assert client.get("/api/runs/12345").status_code == 404
    assert client.delete("/api/runs/12345").status_code == 404
    body = {"scenario_id": "nope", "defense": "none"}
    assert client.post("/api/runs", json=body).status_code == 404


def test_bad_defense_is_a_400(client: TestClient, suite: Suite) -> None:
    body = {"scenario_id": attack_id(suite), "defense": "bogus"}
    response = client.post("/api/runs", json=body)
    assert response.status_code == 400
    assert "bogus" in response.json()["detail"]


def test_invalid_body_is_a_422(client: TestClient) -> None:
    assert client.post("/api/runs", json={"defense": "none"}).status_code == 422


def test_defended_run_blocks_the_attack(client: TestClient, suite: Suite) -> None:
    body = {"scenario_id": attack_id(suite), "defense": "taintwatch"}
    response = client.post("/api/runs", json=body)
    assert response.status_code == 201
    run = response.json()
    assert run["defense"] == "taintwatch"
    assert run["attack_succeeded"] is False
    assert run["blocked"] >= 1
    assert "blocked" in [e["kind"] for e in run["events"]]
    assert run["events"][-1]["kind"] == "finish"
    levels = {seg["integrity"] for seg in run["context"]}
    assert {"SYSTEM", "USER", "UNTRUSTED"} <= levels
    assert "".join(seg["text"] for seg in run["context"]).startswith("You are a helpful")


def test_undefended_run_is_compromised(client: TestClient, suite: Suite) -> None:
    body = {"scenario_id": attack_id(suite), "defense": "none"}
    run = client.post("/api/runs", json=body).json()
    assert run["attack_succeeded"] is True
    assert run["blocked"] == 0


def test_confirm_flag_restores_save_notes(client: TestClient, suite: Suite) -> None:
    sid = confirm_id(suite)
    refused = client.post("/api/runs", json={"scenario_id": sid, "defense": "taintwatch"})
    assert refused.json()["utility_ok"] is False
    approved = client.post(
        "/api/runs", json={"scenario_id": sid, "defense": "taintwatch", "confirm": True}
    )
    assert approved.json()["utility_ok"] is True


def test_run_listing_get_and_delete(client: TestClient, suite: Suite) -> None:
    sid = attack_id(suite)
    first = client.post("/api/runs", json={"scenario_id": sid, "defense": "none"}).json()
    second = client.post("/api/runs", json={"scenario_id": sid, "defense": "taintwatch"}).json()
    listing = client.get("/api/runs").json()
    assert listing["total"] == 2
    assert [r["id"] for r in listing["items"]] == [second["id"], first["id"]]
    assert "events" not in listing["items"][0]
    only = client.get("/api/runs", params={"defense": "none"}).json()
    assert [r["id"] for r in only["items"]] == [first["id"]]
    assert client.get(f"/api/runs/{first['id']}").json()["defense"] == "none"
    assert client.delete(f"/api/runs/{first['id']}").status_code == 204
    assert client.get(f"/api/runs/{first['id']}").status_code == 404
    assert client.get("/api/health").json()["runs"] == 1


def test_list_limits_are_validated(client: TestClient) -> None:
    assert client.get("/api/runs", params={"limit": 0}).status_code == 422
    assert client.get("/api/runs", params={"limit": 501}).status_code == 422
    assert client.get("/api/scenarios", params={"offset": -1}).status_code == 422


def test_stats_endpoint(client: TestClient, suite: Suite) -> None:
    for scenario in suite.attacks[:4]:
        for defense in ("none", "taintwatch"):
            body = {"scenario_id": scenario.id, "defense": defense}
            assert client.post("/api/runs", json=body).status_code == 201
    rows = {row["defense"]: row for row in client.get("/api/stats").json()}
    assert rows["none"]["attack_success_rate"] == 1.0
    assert rows["taintwatch"]["attack_success_rate"] == 0.0
    assert rows["none"]["benign"] == 0
    assert rows["none"]["benign_utility_rate"] is None


def test_record_run_directly(suite: Suite) -> None:
    store = TraceStore()
    run_id = record_run(store, suite.attacks[0], "taintwatch", seed=3)
    run = store.get_run(run_id)
    assert run is not None
    assert run["seed"] == 3
    with pytest.raises(ValueError):
        record_run(store, suite.attacks[0], "bogus")


def test_cors_allows_the_dev_server(client: TestClient) -> None:
    response = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_server_cli_defaults() -> None:
    args = build_parser().parse_args([])
    assert (args.db, args.host, args.port) == ("taintwatch.db", "127.0.0.1", 8000)
