"""Span-level taint tracking."""

from __future__ import annotations

from taintwatch.spans.analysis import Excerpt, redact_below, untrusted_excerpts
from taintwatch.spans.guard_ext import derive_text, ingest_text
from taintwatch.spans.structured import (
    Tagged,
    join_label,
    leaves,
    untrusted_paths,
    unwrap,
    wrap,
)
from taintwatch.spans.tstr import Segment, TStr, interpolate

__all__ = [
    "Excerpt",
    "Segment",
    "TStr",
    "Tagged",
    "derive_text",
    "ingest_text",
    "interpolate",
    "join_label",
    "leaves",
    "redact_below",
    "untrusted_excerpts",
    "untrusted_paths",
    "unwrap",
    "wrap",
]
