import pytest

from taintwatch.server import NewEvent, NewRun, TraceStore


def make_run(
    defense: str = "d1",
    scenario_id: str = "s1",
    *,
    attack: bool = True,
    succeeded: bool = False,
    utility: bool = True,
) -> NewRun:
    return NewRun(
        scenario_id=scenario_id,
        family="attack/x" if attack else "benign/y",
        defense=defense,
        task="do it",
        seed=7,
        is_attack=attack,
        attack_succeeded=succeeded,
        utility_ok=utility,
        blocked=1,
        calls=2,
        steps=3,
        truncated=False,
        answer="done",
        context=[{"text": "hi", "integrity": "USER", "confidentiality": "PUBLIC", "sources": []}],
        events=(
            NewEvent(1, "call", "web.fetch", (("url", "https://a.test"),), ""),
            NewEvent(2, "blocked", "shell.run", (("cmd", "ls"),), "rule x"),
        ),
    )


def test_add_and_get_roundtrip() -> None:
    store = TraceStore()
    run_id = store.add_run(make_run())
    run = store.get_run(run_id)
    assert run is not None
    assert run["id"] == run_id
    assert (run["scenario_id"], run["defense"], run["seed"]) == ("s1", "d1", 7)
    assert run["is_attack"] is True
    assert run["attack_succeeded"] is False
    assert run["truncated"] is False
    assert run["answer"] == "done"
    assert run["context"][0]["text"] == "hi"
    assert [e["kind"] for e in run["events"]] == ["call", "blocked"]
    assert run["events"][0]["args"] == [{"name": "url", "value": "https://a.test"}]
    assert run["events"][1]["detail"] == "rule x"


def test_missing_run_is_none() -> None:
    assert TraceStore().get_run(99) is None


def test_list_orders_newest_first_and_filters() -> None:
    store = TraceStore()
    a = store.add_run(make_run("d1", "s1"))
    b = store.add_run(make_run("d2", "s1"))
    c = store.add_run(make_run("d1", "s2"))
    assert [r["id"] for r in store.list_runs()] == [c, b, a]
    assert [r["id"] for r in store.list_runs(defense="d1")] == [c, a]
    assert [r["id"] for r in store.list_runs(scenario_id="s1")] == [b, a]
    assert [r["id"] for r in store.list_runs(defense="d1", scenario_id="s2")] == [c]
    assert store.count_runs() == 3
    assert store.count_runs(defense="d1") == 2


def test_list_paginates() -> None:
    store = TraceStore()
    ids = [store.add_run(make_run()) for _ in range(5)]
    assert [r["id"] for r in store.list_runs(limit=2, offset=1)] == [ids[3], ids[2]]


def test_list_rejects_bad_paging() -> None:
    store = TraceStore()
    with pytest.raises(ValueError):
        store.list_runs(limit=0)
    with pytest.raises(ValueError):
        store.list_runs(offset=-1)


def test_stats_aggregate_per_defense() -> None:
    store = TraceStore()
    store.add_run(make_run("d1", attack=True, succeeded=True))
    store.add_run(make_run("d1", attack=True, succeeded=False))
    store.add_run(make_run("d1", attack=False, utility=True))
    store.add_run(make_run("d1", attack=False, utility=False))
    store.add_run(make_run("d2", attack=True, succeeded=False))
    rows = {row["defense"]: row for row in store.stats()}
    assert rows["d1"]["runs"] == 4
    assert (rows["d1"]["attacks"], rows["d1"]["attack_successes"]) == (2, 1)
    assert (rows["d1"]["benign"], rows["d1"]["benign_ok"]) == (2, 1)
    assert (rows["d2"]["attacks"], rows["d2"]["benign"]) == (1, 0)
    assert list(rows) == ["d1", "d2"]


def test_delete_and_clear() -> None:
    store = TraceStore()
    run_id = store.add_run(make_run())
    store.add_run(make_run())
    assert store.delete_run(run_id) is True
    assert store.delete_run(run_id) is False
    assert store.get_run(run_id) is None
    assert store.clear() == 1
    assert store.count_runs() == 0


def test_file_database_persists(tmp_path: object) -> None:
    path = f"{tmp_path}/runs.db"
    first = TraceStore(path)
    run_id = first.add_run(make_run())
    first.close()
    second = TraceStore(path)
    assert second.get_run(run_id) is not None
    second.close()
