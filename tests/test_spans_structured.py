from taintwatch.labels import Integrity, Label
from taintwatch.spans import Tagged, TStr, join_label, leaves, untrusted_paths, unwrap, wrap

BAD = Label(Integrity.UNTRUSTED, sources=frozenset({"web"}))
GOOD = Label(Integrity.USER, sources=frozenset({"user"}))


def test_wrap_unwrap_roundtrip() -> None:
    data = {"a": "x", "b": [1, "y", None], "c": {"d": True}, "e": (1, "z")}
    assert unwrap(wrap(data, BAD)) == data


def test_wrap_labels_every_leaf() -> None:
    wrapped = wrap({"a": "x", "b": ["y"], "n": 3}, BAD)
    assert isinstance(wrapped["a"], TStr)
    assert wrapped["n"] == Tagged(3, BAD)
    assert join_label(wrapped).integrity is Integrity.UNTRUSTED


def test_wrap_keeps_existing_labels_and_container_types() -> None:
    wrapped = wrap({"a": TStr.of("x", GOOD), "t": (1, "a"), "l": [1]}, BAD)
    assert wrapped["a"].label_at(0) == GOOD
    assert isinstance(wrapped["t"], tuple)
    assert isinstance(wrapped["l"], list)


def test_plain_data_is_literal() -> None:
    assert join_label({"a": 1, "b": ["x"]}) == Label()


def test_leaves_report_paths() -> None:
    wrapped = wrap({"a": "x", "b": ["y"]}, BAD)
    assert dict(leaves(wrapped)) == {"$.a": BAD, "$.b[0]": BAD}


def test_untrusted_paths_only_lists_low_integrity_leaves() -> None:
    data = {"user": TStr.of("hi", GOOD), "page": TStr.of("evil", BAD), "n": 3}
    assert untrusted_paths(data, Integrity.USER) == ["$.page"]
