"""Span-level taint tracking for strings.

A ``TStr`` is an immutable string plus a list of contiguous segments, each with
its own ``Label``. Segments always cover the whole text, in order, with adjacent
equal labels merged. Plain ``str`` operands are treated as program literals and
get the bottom label (fully trusted, public).
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from taintwatch.labels import Integrity, Label

Piece = tuple[str, Label]
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


@dataclass(frozen=True, slots=True)
class Segment:
    start: int
    end: int
    label: Label


class TStr:
    """A string whose character ranges carry individual labels.

    Build instances with ``TStr.of`` or the operations below, not the constructor.
    """

    __slots__ = ("_segments", "_starts", "_text")

    def __init__(self, text: str, segments: tuple[Segment, ...]) -> None:
        self._text = text
        self._segments = segments
        self._starts = tuple(s.start for s in segments)

    @classmethod
    def of(cls, text: str, label: Label | None = None) -> TStr:
        """A string whose every character carries ``label`` (bottom label by default)."""
        if not text:
            return cls("", ())
        chosen = label if label is not None else Label()
        return cls(text, (Segment(0, len(text), chosen),))

    @property
    def text(self) -> str:
        return self._text

    @property
    def segments(self) -> tuple[Segment, ...]:
        return self._segments

    def __len__(self) -> int:
        return len(self._text)

    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"TStr({self._text!r}, {len(self._segments)} segment(s))"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TStr):
            return self._text == other._text and self._segments == other._segments
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._text, self._segments))

    def label_at(self, index: int) -> Label:
        """Label of the character at a non-negative ``index``."""
        if not 0 <= index < len(self._text):
            raise IndexError("string index out of range")
        return self._segments[bisect_right(self._starts, index) - 1].label

    def overall_label(self) -> Label:
        """The join of every segment label. The empty string gets the bottom label."""
        return Label.join_all(s.label for s in self._segments)

    def ranges_below(self, floor: Integrity) -> list[tuple[int, int]]:
        """Merged ``(start, end)`` ranges whose integrity is below ``floor``."""
        ranges: list[tuple[int, int]] = []
        for seg in self._segments:
            if seg.label.integrity >= floor:
                continue
            if ranges and ranges[-1][1] == seg.start:
                ranges[-1] = (ranges[-1][0], seg.end)
            else:
                ranges.append((seg.start, seg.end))
        return ranges

    def _pieces(self) -> list[Piece]:
        return [(self._text[s.start : s.end], s.label) for s in self._segments]

    def _piece_range(self, start: int, stop: int) -> list[Piece]:
        out: list[Piece] = []
        for seg in self._segments:
            lo = max(seg.start, start)
            hi = min(seg.end, stop)
            if lo < hi:
                out.append((self._text[lo:hi], seg.label))
        return out

    def _slice(self, start: int, stop: int) -> TStr:
        return _build(self._piece_range(start, stop))

    def __add__(self, other: TStr | str) -> TStr:
        return _build([*self._pieces(), *_coerce(other)._pieces()])

    def __radd__(self, other: str) -> TStr:
        return _build([*_coerce(other)._pieces(), *self._pieces()])

    def __getitem__(self, key: int | slice) -> TStr:
        if isinstance(key, slice):
            indices = range(*key.indices(len(self._text)))
            if indices.step == 1:
                return self._slice(indices.start, indices.stop)
            return _build((self._text[i], self.label_at(i)) for i in indices)
        char = self._text[key]
        index = key if key >= 0 else key + len(self._text)
        return _build([(char, self.label_at(index))])

    def startswith(self, prefix: str) -> bool:
        return self._text.startswith(prefix)

    def strip(self, chars: str | None = None) -> TStr:
        left = len(self._text) - len(self._text.lstrip(chars))
        right = len(self._text.rstrip(chars))
        if right <= left:
            return _build([])
        return self._slice(left, right)

    def _map(self, fn: Callable[[str], str]) -> TStr:
        return _build((fn(text), label) for text, label in self._pieces())

    def lower(self) -> TStr:
        return self._map(str.lower)

    def upper(self) -> TStr:
        return self._map(str.upper)

    def split(self, sep: str, maxsplit: int = -1) -> list[TStr]:
        """Like ``str.split(sep, maxsplit)`` but every part keeps its labels."""
        if not sep:
            raise ValueError("empty separator")
        parts: list[TStr] = []
        pos = 0
        done = 0
        while maxsplit < 0 or done < maxsplit:
            idx = self._text.find(sep, pos)
            if idx < 0:
                break
            parts.append(self._slice(pos, idx))
            pos = idx + len(sep)
            done += 1
        parts.append(self._slice(pos, len(self._text)))
        return parts

    def replace(self, old: str, new: TStr | str, count: int = -1) -> TStr:
        """Like ``str.replace`` but ``new`` keeps its own labels."""
        if not old:
            raise ValueError("empty pattern")
        replacement = _coerce(new)._pieces()
        pieces: list[Piece] = []
        pos = 0
        done = 0
        while count < 0 or done < count:
            idx = self._text.find(old, pos)
            if idx < 0:
                break
            pieces.extend(self._piece_range(pos, idx))
            pieces.extend(replacement)
            pos = idx + len(old)
            done += 1
        pieces.extend(self._piece_range(pos, len(self._text)))
        return _build(pieces)

    @staticmethod
    def join(sep: TStr | str, parts: Iterable[TStr | str]) -> TStr:
        separator = _coerce(sep)._pieces()
        pieces: list[Piece] = []
        for i, part in enumerate(parts):
            if i:
                pieces.extend(separator)
            pieces.extend(_coerce(part)._pieces())
        return _build(pieces)


def _coerce(value: TStr | str) -> TStr:
    return value if isinstance(value, TStr) else TStr.of(value)


def _build(pieces: Iterable[Piece]) -> TStr:
    """Concatenate ``(text, label)`` pieces, dropping empties and merging neighbours."""
    parts: list[str] = []
    segments: list[Segment] = []
    pos = 0
    for text, label in pieces:
        if not text:
            continue
        end = pos + len(text)
        if segments and segments[-1].label == label:
            segments[-1] = Segment(segments[-1].start, end, label)
        else:
            segments.append(Segment(pos, end, label))
        parts.append(text)
        pos = end
    return TStr("".join(parts), tuple(segments))


def interpolate(template: TStr | str, values: Mapping[str, TStr | str]) -> TStr:
    """Fill ``{name}`` placeholders. Substituted text is never re-expanded."""
    tpl = _coerce(template)
    pieces: list[Piece] = []
    pos = 0
    for match in _PLACEHOLDER.finditer(tpl.text):
        pieces.extend(tpl._piece_range(pos, match.start()))
        name = match.group(1)
        if name not in values:
            raise KeyError(name)
        pieces.extend(_coerce(values[name])._pieces())
        pos = match.end()
    pieces.extend(tpl._piece_range(pos, len(tpl)))
    return _build(pieces)
