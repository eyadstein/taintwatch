import pytest

from taintwatch.dsl.errors import DslError
from taintwatch.dsl.lexer import TokenKind, tokenize


def test_tokenizes_a_rule_line() -> None:
    tokens = tokenize("rule r: block shell.* when integrity < user")
    assert [t.text for t in tokens] == [
        "rule", "r", ":", "block", "shell.*", "when", "integrity", "<", "user", "",
    ]
    assert tokens[-1].kind is TokenKind.EOF
    assert tokens[7].kind is TokenKind.OP


def test_comments_are_skipped_and_lines_tracked() -> None:
    tokens = tokenize("# hi\nrule x")
    assert tokens[0].text == "rule"
    assert (tokens[0].line, tokens[0].col) == (2, 1)


def test_string_escapes() -> None:
    tokens = tokenize(r'"a \"b\" c"')
    assert tokens[0].kind is TokenKind.STRING
    assert tokens[0].text == 'a "b" c'


def test_two_character_operators() -> None:
    assert [t.text for t in tokenize("<= >= < >")[:-1]] == ["<=", ">=", "<", ">"]


def test_unterminated_string() -> None:
    with pytest.raises(DslError, match="unterminated"):
        tokenize('rule "oops')


def test_unexpected_character_reports_position() -> None:
    with pytest.raises(DslError) as info:
        tokenize("rule @")
    assert (info.value.line, info.value.col) == (1, 6)
