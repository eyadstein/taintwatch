import pytest

from taintwatch.dsl import DslError, parse

SOURCE = '''
rule a: block shell.* when integrity < user because "no"
rule b: confirm fs.write(content) when integrity < tool_output or confidentiality > internal
'''


def test_parses_two_rules() -> None:
    program = parse(SOURCE)
    assert [r.name for r in program.rules] == ["a", "b"]
    a, b = program.rules
    assert (a.action, a.tool, a.arg, a.reason) == ("block", "shell.*", "*", "no")
    assert (b.action, b.arg) == ("confirm", "content")
    assert [c.subject for c in b.conditions] == ["integrity", "confidentiality"]


def test_empty_program() -> None:
    assert parse("# nothing here\n").rules == ()


def test_missing_colon() -> None:
    with pytest.raises(DslError, match="expected ':'"):
        parse("rule a block t when integrity < user")


def test_missing_when() -> None:
    with pytest.raises(DslError, match="expected 'when'"):
        parse("rule a: block t")


def test_bad_action() -> None:
    with pytest.raises(DslError, match="expected 'block' or 'confirm'"):
        parse("rule a: allow t when integrity < user")


def test_keyword_cannot_be_a_name() -> None:
    with pytest.raises(DslError, match="keyword"):
        parse("rule block: block t when integrity < user")


def test_bad_subject() -> None:
    with pytest.raises(DslError, match="expected 'integrity' or 'confidentiality'"):
        parse("rule a: block t when color < user")


def test_unclosed_argument() -> None:
    with pytest.raises(DslError, match="expected '\\)'"):
        parse("rule a: block t(arg when integrity < user")


def test_error_position_spans_lines() -> None:
    with pytest.raises(DslError) as info:
        parse("\n\nrule a block")
    assert (info.value.line, info.value.col) == (3, 8)


def test_truncated_rule() -> None:
    with pytest.raises(DslError, match="a rule name"):
        parse("rule")
