import pytest
from fastapi.testclient import TestClient

from taintwatch.bench import FAMILIES, GOALS, build_suite
from taintwatch.server import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(":memory:", suite=build_suite(20, 14)))


def test_families_cover_every_scenario(client: TestClient) -> None:
    items = client.get("/api/families").json()
    assert sum(item["count"] for item in items) == 34
    attacks = {i["family"]: i["count"] for i in items if i["is_attack"]}
    benign = {i["family"]: i["count"] for i in items if not i["is_attack"]}
    assert attacks == {f"attack/{goal}": 4 for goal in GOALS}
    assert benign == {f"benign/{family}": 2 for family in FAMILIES}


def test_families_are_sorted(client: TestClient) -> None:
    names = [item["family"] for item in client.get("/api/families").json()]
    assert names == sorted(names)


def test_listing_can_be_filtered_by_a_listed_family(client: TestClient) -> None:
    page = client.get("/api/scenarios", params={"family": "attack/shell_exec"}).json()
    assert page["total"] == 4
    assert all(item["family"] == "attack/shell_exec" for item in page["items"])
