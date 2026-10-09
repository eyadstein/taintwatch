"""Recursive-descent parser for the Taintwatch policy language.

Grammar::

    program   := rule*
    rule      := "rule" NAME ":" ACTION TOOL [ "(" ARG ")" ]
                 "when" condition ( "or" condition )*
                 [ "because" STRING ]
    condition := SUBJECT OP LEVEL
    ACTION    := "block" | "confirm"
    SUBJECT   := "integrity" | "confidentiality"
"""

from __future__ import annotations

from taintwatch.dsl.errors import DslError
from taintwatch.dsl.lexer import Token, TokenKind, tokenize
from taintwatch.dsl.nodes import Condition, Program, RuleNode

KEYWORDS = frozenset({"rule", "when", "or", "because", "block", "confirm"})
ACTIONS = frozenset({"block", "confirm"})
SUBJECTS = frozenset({"integrity", "confidentiality"})


def _describe(token: Token) -> str:
    return "end of input" if token.kind is TokenKind.EOF else repr(token.text)


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        token = self._tokens[self._pos]
        if token.kind is not TokenKind.EOF:
            self._pos += 1
        return token

    def _fail(self, message: str, token: Token | None = None) -> DslError:
        at = token if token is not None else self._peek()
        return DslError(message, at.line, at.col)

    def _at_keyword(self, keyword: str) -> bool:
        token = self._peek()
        return token.kind is TokenKind.WORD and token.text == keyword

    def _expect(self, kind: TokenKind, what: str) -> Token:
        token = self._peek()
        if token.kind is not kind:
            raise self._fail(f"expected {what}, found {_describe(token)}")
        return self._advance()

    def _expect_keyword(self, keyword: str) -> Token:
        if not self._at_keyword(keyword):
            raise self._fail(f"expected '{keyword}', found {_describe(self._peek())}")
        return self._advance()

    def _expect_name(self, what: str) -> Token:
        token = self._expect(TokenKind.WORD, what)
        if token.text in KEYWORDS:
            raise self._fail(f"keyword {token.text!r} cannot be used as {what}", token)
        return token

    def parse_program(self) -> Program:
        rules: list[RuleNode] = []
        while self._peek().kind is not TokenKind.EOF:
            rules.append(self._parse_rule())
        return Program(tuple(rules))

    def _parse_rule(self) -> RuleNode:
        start = self._expect_keyword("rule")
        name = self._expect_name("a rule name")
        self._expect(TokenKind.COLON, "':'")
        action = self._expect(TokenKind.WORD, "an action")
        if action.text not in ACTIONS:
            raise self._fail(
                f"expected 'block' or 'confirm', found {_describe(action)}", action
            )
        tool = self._expect_name("a tool pattern")
        arg = "*"
        if self._peek().kind is TokenKind.LPAREN:
            self._advance()
            arg = self._expect_name("an argument pattern").text
            self._expect(TokenKind.RPAREN, "')'")
        self._expect_keyword("when")
        conditions = [self._parse_condition()]
        while self._at_keyword("or"):
            self._advance()
            conditions.append(self._parse_condition())
        reason = ""
        if self._at_keyword("because"):
            self._advance()
            reason = self._expect(TokenKind.STRING, "a quoted reason").text
        return RuleNode(
            name=name.text,
            action=action.text,
            tool=tool.text,
            arg=arg,
            conditions=tuple(conditions),
            reason=reason,
            line=start.line,
            col=start.col,
        )

    def _parse_condition(self) -> Condition:
        subject = self._expect(TokenKind.WORD, "'integrity' or 'confidentiality'")
        if subject.text not in SUBJECTS:
            raise self._fail(
                f"expected 'integrity' or 'confidentiality', found {_describe(subject)}",
                subject,
            )
        op = self._expect(TokenKind.OP, "a comparison operator")
        level = self._expect_name("a level")
        return Condition(subject.text, op.text, level.text, subject.line, subject.col)


def parse(text: str) -> Program:
    """Parse policy source text into a syntax tree."""
    return _Parser(tokenize(text)).parse_program()
