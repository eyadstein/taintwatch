"""Tokenizer for the Taintwatch policy language."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from taintwatch.dsl.errors import DslError


class TokenKind(StrEnum):
    WORD = "word"
    STRING = "string"
    OP = "operator"
    LPAREN = "'('"
    RPAREN = "')'"
    COLON = "':'"
    EOF = "end of input"


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    text: str
    line: int
    col: int


_SPEC: tuple[tuple[str, str], ...] = (
    ("SKIP", r"[ \t\r\n]+|#[^\n]*"),
    ("STRING", r'"(?:[^"\\\n]|\\.)*"'),
    ("OP", r"<=|>=|<|>"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("COLON", r":"),
    ("WORD", r"[A-Za-z0-9_.*?\-]+"),
)
_MASTER = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in _SPEC))
_ESCAPE = re.compile(r"\\(.)")
_KINDS: dict[str, TokenKind] = {
    "OP": TokenKind.OP,
    "LPAREN": TokenKind.LPAREN,
    "RPAREN": TokenKind.RPAREN,
    "COLON": TokenKind.COLON,
    "WORD": TokenKind.WORD,
}


def tokenize(text: str) -> list[Token]:
    """Split policy source into tokens. Whitespace and ``#`` comments are dropped."""
    tokens: list[Token] = []
    pos = 0
    line = 1
    line_start = 0
    while pos < len(text):
        col = pos - line_start + 1
        match = _MASTER.match(text, pos)
        if match is None:
            if text[pos] == '"':
                raise DslError("unterminated string literal", line, col)
            raise DslError(f"unexpected character {text[pos]!r}", line, col)
        lexeme = match.group()
        kind = match.lastgroup or ""
        if kind == "SKIP":
            newlines = lexeme.count("\n")
            if newlines:
                line += newlines
                line_start = pos + lexeme.rfind("\n") + 1
        elif kind == "STRING":
            body = _ESCAPE.sub(r"\1", lexeme[1:-1])
            tokens.append(Token(TokenKind.STRING, body, line, col))
        else:
            tokens.append(Token(_KINDS[kind], lexeme, line, col))
        pos = match.end()
    tokens.append(Token(TokenKind.EOF, "", line, pos - line_start + 1))
    return tokens
