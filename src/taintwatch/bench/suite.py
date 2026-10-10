"""Assemble the full benchmark suite and read/write it as JSON Lines."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from taintwatch.bench.attacks import generate_attacks
from taintwatch.bench.benign import generate_benign
from taintwatch.bench.scenario import Scenario


@dataclass(frozen=True, slots=True)
class Suite:
    attacks: tuple[Scenario, ...]
    benign: tuple[Scenario, ...]
    seed: int

    @property
    def scenarios(self) -> tuple[Scenario, ...]:
        return self.attacks + self.benign

    def counts(self) -> dict[str, int]:
        """Scenario count per family, sorted by family name."""
        return dict(sorted(Counter(s.family for s in self.scenarios).items()))


def build_suite(attacks: int = 600, benign: int = 200, seed: int = 7) -> Suite:
    return Suite(
        tuple(generate_attacks(attacks, seed)),
        tuple(generate_benign(benign, seed)),
        seed,
    )


def write_jsonl(scenarios: Iterable[Scenario], path: str | Path) -> int:
    """Write one JSON object per line. Returns the number of scenarios written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for scenario in scenarios:
            handle.write(json.dumps(scenario.to_dict(), sort_keys=True))
            handle.write("\n")
            written += 1
    return written


def read_jsonl(path: str | Path) -> list[Scenario]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [Scenario.from_dict(json.loads(line)) for line in lines if line.strip()]
