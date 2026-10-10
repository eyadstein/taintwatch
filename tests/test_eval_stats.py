import pytest

from taintwatch.evaluation import Rate, mcnemar_exact, median, percentile, wilson_interval


def test_wilson_zero_successes() -> None:
    low, high = wilson_interval(0, 600)
    assert low == pytest.approx(0.0, abs=1e-12)
    assert high == pytest.approx(3.841459 / (600 + 3.841459), rel=1e-4)


def test_wilson_half() -> None:
    low, high = wilson_interval(50, 100)
    assert low == pytest.approx(0.4038, abs=1e-3)
    assert high == pytest.approx(0.5962, abs=1e-3)


def test_wilson_all_successes() -> None:
    low, high = wilson_interval(100, 100)
    assert low == pytest.approx(0.9630, abs=1e-3)
    assert high == pytest.approx(1.0, abs=1e-9)


@pytest.mark.parametrize(("hits", "total"), [(1, 0), (5, 3), (-1, 3)])
def test_wilson_rejects_bad_input(hits: int, total: int) -> None:
    with pytest.raises(ValueError):
        wilson_interval(hits, total)


def test_rate_basics() -> None:
    rate = Rate(3, 10)
    assert rate.value == pytest.approx(0.3)
    assert rate.percent() == "30.0%"
    assert rate.fmt().startswith("30.0% [")
    low, high = rate.interval()
    assert low < 0.3 < high


def test_rate_with_no_runs() -> None:
    rate = Rate(0, 0)
    assert rate.value == 0.0
    assert rate.interval() == (0.0, 1.0)
    assert rate.fmt() == "n/a"
    assert rate.percent() == "n/a"


def test_rate_to_dict() -> None:
    data = Rate(1, 4).to_dict()
    assert data["hits"] == 1
    assert data["total"] == 4
    assert data["rate"] == pytest.approx(0.25)
    assert data["lo"] < 0.25 < data["hi"]


def test_percentiles() -> None:
    values = [4.0, 1.0, 3.0, 2.0]
    assert percentile(values, 0) == 1.0
    assert percentile(values, 100) == 4.0
    assert percentile(values, 50) == pytest.approx(2.5)
    assert percentile(values, 25) == pytest.approx(1.75)
    assert median([3.0, 1.0, 2.0]) == 2.0
    assert percentile([5.0], 95) == 5.0


def test_percentile_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        percentile([], 50)
    with pytest.raises(ValueError):
        percentile([1.0], 101)


def test_mcnemar_exact() -> None:
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(5, 0) == pytest.approx(0.0625)
    assert mcnemar_exact(3, 3) == 1.0
    assert mcnemar_exact(10, 0) == pytest.approx(2 / 1024)
    assert mcnemar_exact(0, 5) == mcnemar_exact(5, 0)
    assert mcnemar_exact(400, 0) < 1e-100


def test_mcnemar_rejects_negative_counts() -> None:
    with pytest.raises(ValueError):
        mcnemar_exact(-1, 2)
