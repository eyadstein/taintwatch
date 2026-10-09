import pytest

from taintwatch.agent import extract_directives, render_directive
from taintwatch.labels import Integrity, Label
from taintwatch.spans import TStr

BAD = Label(Integrity.UNTRUSTED, sources=frozenset({"web"}))
GOOD = Label(Integrity.USER, sources=frozenset({"user"}))


def test_extracts_a_call_with_its_labels() -> None:
    text = TStr.of("hello ", GOOD) + TStr.of(render_directive("shell.run", {"cmd": "ls -la"}), BAD)
    (request,) = extract_directives(text)
    assert request.tool == "shell.run"
    assert request.args["cmd"].text == "ls -la"
    assert request.args["cmd"].overall_label() == BAD


def test_labels_are_per_span() -> None:
    text = TStr.of('<<call echo.say msg="', GOOD) + TStr.of("hi", BAD) + TStr.of('">>', GOOD)
    (request,) = extract_directives(text)
    assert request.args["msg"].overall_label() == BAD


def test_multiple_calls_and_arguments() -> None:
    raw = (
        "a "
        + render_directive("t.one", {"x": "1", "y": "2"})
        + " b "
        + render_directive("t.two", {"z": "3"})
    )
    first, second = extract_directives(TStr.of(raw, BAD))
    assert (first.tool, sorted(first.args)) == ("t.one", ["x", "y"])
    assert (second.tool, second.args["z"].text) == ("t.two", "3")


def test_no_directives_and_no_args() -> None:
    assert extract_directives(TStr.of("nothing here")) == []
    (request,) = extract_directives(TStr.of("<<call a.b>>"))
    assert request.args == {}


def test_malformed_directives_are_ignored() -> None:
    assert extract_directives(TStr.of("<<call shell.run cmd=oops>>")) == []


def test_render_format() -> None:
    rendered = render_directive("t.x", {"a": "1", "b": "two words"})
    assert rendered == '<<call t.x a="1" b="two words">>'


def test_render_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        render_directive("t.x", {"a": 'say "hi"'})
    with pytest.raises(ValueError):
        render_directive("t.x", {"not valid": "1"})
