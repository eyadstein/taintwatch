import pytest

from taintwatch.labels import Integrity, Label
from taintwatch.spans import TStr, interpolate

BAD = Label(Integrity.UNTRUSTED, sources=frozenset({"web"}))
GOOD = Label(Integrity.USER, sources=frozenset({"user"}))


def test_of_and_basics() -> None:
    t = TStr.of("abc", BAD)
    assert len(t) == 3
    assert str(t) == "abc"
    assert t.label_at(1) == BAD
    assert t.overall_label() == BAD


def test_empty_string_has_bottom_label() -> None:
    t = TStr.of("", BAD)
    assert t.segments == ()
    assert t.overall_label() == Label()


def test_concat_keeps_per_span_labels() -> None:
    t = TStr.of("ab", GOOD) + TStr.of("cd", BAD)
    assert t.text == "abcd"
    assert t.label_at(1) == GOOD
    assert t.label_at(2) == BAD
    assert len(t.segments) == 2


def test_plain_strings_are_literals() -> None:
    t = "x" + TStr.of("y", BAD) + "z"
    assert t.text == "xyz"
    assert t.label_at(0) == Label()
    assert t.label_at(1) == BAD
    assert t.label_at(2) == Label()


def test_adjacent_equal_labels_merge() -> None:
    t = TStr.of("a", BAD) + TStr.of("b", BAD)
    assert [(s.start, s.end) for s in t.segments] == [(0, 2)]


def test_slicing_and_indexing() -> None:
    t = TStr.of("ab", GOOD) + TStr.of("cd", BAD)
    middle = t[1:3]
    assert middle.text == "bc"
    assert (middle.label_at(0), middle.label_at(1)) == (GOOD, BAD)
    assert t[3].label_at(0) == BAD
    assert t[-1].text == "d"
    assert t[2:2].text == ""
    assert t[10:].text == ""
    with pytest.raises(IndexError):
        t[4]


def test_stepped_slices() -> None:
    t = TStr.of("ab", GOOD) + TStr.of("cd", BAD)
    reversed_t = t[::-1]
    assert reversed_t.text == "dcba"
    assert reversed_t.label_at(0) == BAD
    assert reversed_t.label_at(3) == GOOD
    every_other = t[::2]
    assert every_other.text == "ac"
    assert (every_other.label_at(0), every_other.label_at(1)) == (GOOD, BAD)


def test_every_slice_keeps_labels_aligned() -> None:
    t = TStr.of("ab", GOOD) + TStr.of("cde", BAD) + TStr.of("f", GOOD)
    for i in range(7):
        for j in range(i, 7):
            piece = t[i:j]
            assert piece.text == t.text[i:j]
            for k in range(len(piece)):
                assert piece.label_at(k) == t.label_at(i + k)


def test_strip() -> None:
    t = TStr.of("  ", GOOD) + TStr.of("hi", BAD) + TStr.of("  ", GOOD)
    stripped = t.strip()
    assert stripped.text == "hi"
    assert stripped.overall_label() == BAD
    assert TStr.of("   ", BAD).strip().text == ""
    assert TStr.of("xxhixx", BAD).strip("x").text == "hi"


@pytest.mark.parametrize(
    ("text", "sep", "maxsplit"),
    [
        ("a,b,c", ",", -1),
        ("a,b,c", ",", 1),
        ("a,b,c", ",", 0),
        (",a,,b,", ",", -1),
        ("abc", "x", -1),
        ("a--b--c", "--", -1),
        ("", ",", -1),
    ],
)
def test_split_matches_str_split(text: str, sep: str, maxsplit: int) -> None:
    parts = TStr.of(text, BAD).split(sep, maxsplit)
    assert [p.text for p in parts] == text.split(sep, maxsplit)


def test_split_keeps_labels_per_part() -> None:
    t = TStr.of("a,b", GOOD) + TStr.of(",c", BAD)
    parts = t.split(",")
    assert [p.text for p in parts] == ["a", "b", "c"]
    assert [p.overall_label().integrity for p in parts] == [
        Integrity.USER,
        Integrity.USER,
        Integrity.UNTRUSTED,
    ]
    rest = t.split(",", 1)[1]
    assert rest.text == "b,c"
    assert rest.overall_label().integrity is Integrity.UNTRUSTED


def test_split_rejects_empty_separator() -> None:
    with pytest.raises(ValueError):
        TStr.of("abc", BAD).split("")


def test_replace_keeps_replacement_labels() -> None:
    result = TStr.of("cat sat", GOOD).replace("sat", TStr.of("RUN", BAD))
    assert result.text == "cat RUN"
    assert result.label_at(0) == GOOD
    assert result.label_at(4) == BAD
    assert result.ranges_below(Integrity.USER) == [(4, 7)]


def test_replace_count_matches_str_replace() -> None:
    t = TStr.of("aaa", GOOD)
    assert t.replace("a", "b", 1).text == "baa"
    assert t.replace("a", "b", 0).text == "aaa"
    assert t.replace("a", "b").text == "bbb"


def test_join() -> None:
    t = TStr.join(", ", [TStr.of("a", BAD), "b", TStr.of("c", GOOD)])
    assert t.text == "a, b, c"
    assert t.label_at(0) == BAD
    assert t.label_at(3) == Label()
    assert t.label_at(6) == GOOD
    assert TStr.join(",", []).text == ""


def test_case_mapping_keeps_labels() -> None:
    t = TStr.of("Ab", GOOD) + TStr.of("Cd", BAD)
    upper = t.upper()
    assert upper.text == "ABCD"
    assert (upper.label_at(1), upper.label_at(2)) == (GOOD, BAD)
    assert t.lower().text == "abcd"


def test_length_changing_case_mapping() -> None:
    upper = TStr.of("\u00df", BAD).upper()
    assert upper.text == "SS"
    assert upper.label_at(1) == BAD


def test_ranges_below_merges_adjacent_runs() -> None:
    tool = Label(Integrity.TOOL_OUTPUT)
    t = TStr.of("a", BAD) + TStr.of("b", tool) + TStr.of("c", GOOD)
    assert t.ranges_below(Integrity.USER) == [(0, 2)]
    assert t.ranges_below(Integrity.TOOL_OUTPUT) == [(0, 1)]


def test_interpolate() -> None:
    t = interpolate("run {cmd} now", {"cmd": TStr.of("ls", BAD)})
    assert t.text == "run ls now"
    assert t.label_at(0) == Label()
    assert t.label_at(4) == BAD
    assert t.ranges_below(Integrity.USER) == [(4, 6)]


def test_interpolate_does_not_reexpand_values() -> None:
    t = interpolate("{a}", {"a": TStr.of("{b}", BAD), "b": "x"})
    assert t.text == "{b}"


def test_interpolate_missing_name() -> None:
    with pytest.raises(KeyError):
        interpolate("{nope}", {})


def test_equality_and_hash() -> None:
    assert TStr.of("a", BAD) == TStr.of("a", BAD)
    assert TStr.of("a", BAD) != TStr.of("a", GOOD)
    assert hash(TStr.of("a", BAD)) == hash(TStr.of("a", BAD))
    assert TStr.of("a", BAD) != "a"
