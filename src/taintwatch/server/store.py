"""SQLite storage for runs, their events and their labeled context."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Any

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scenario_id TEXT NOT NULL,
    family TEXT NOT NULL,
    defense TEXT NOT NULL,
    task TEXT NOT NULL,
    seed INTEGER NOT NULL,
    is_attack INTEGER NOT NULL,
    attack_succeeded INTEGER NOT NULL,
    utility_ok INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    calls INTEGER NOT NULL,
    steps INTEGER NOT NULL,
    truncated INTEGER NOT NULL,
    answer TEXT NOT NULL,
    context_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_defense ON runs(defense);
CREATE INDEX IF NOT EXISTS idx_runs_scenario ON runs(scenario_id);
CREATE TABLE IF NOT EXISTS events (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    step INTEGER NOT NULL,
    kind TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_json TEXT NOT NULL,
    detail TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
"""

SUMMARY_COLUMNS = (
    "id, created_at, scenario_id, family, defense, task, seed, is_attack, "
    "attack_succeeded, utility_ok, blocked, calls, steps, truncated"
)


@dataclass(frozen=True, slots=True)
class NewEvent:
    step: int
    kind: str
    tool: str
    args: tuple[tuple[str, str], ...]
    detail: str


@dataclass(frozen=True, slots=True)
class NewRun:
    scenario_id: str
    family: str
    defense: str
    task: str
    seed: int
    is_attack: bool
    attack_succeeded: bool
    utility_ok: bool
    blocked: int
    calls: int
    steps: int
    truncated: bool
    answer: str
    context: list[dict[str, Any]]
    events: tuple[NewEvent, ...] = ()


def _summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "scenario_id": row["scenario_id"],
        "family": row["family"],
        "defense": row["defense"],
        "task": row["task"],
        "seed": row["seed"],
        "is_attack": bool(row["is_attack"]),
        "attack_succeeded": bool(row["attack_succeeded"]),
        "utility_ok": bool(row["utility_ok"]),
        "blocked": row["blocked"],
        "calls": row["calls"],
        "steps": row["steps"],
        "truncated": bool(row["truncated"]),
    }


def _where(defense: str | None, scenario_id: str | None) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    if defense is not None:
        clauses.append("defense = ?")
        params.append(defense)
    if scenario_id is not None:
        clauses.append("scenario_id = ?")
        params.append(scenario_id)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


class TraceStore:
    """Thread-safe SQLite store. Use ``":memory:"`` for tests."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def add_run(self, run: NewRun) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO runs (scenario_id, family, defense, task, seed, is_attack, "
                "attack_succeeded, utility_ok, blocked, calls, steps, truncated, answer, "
                "context_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.scenario_id,
                    run.family,
                    run.defense,
                    run.task,
                    run.seed,
                    int(run.is_attack),
                    int(run.attack_succeeded),
                    int(run.utility_ok),
                    run.blocked,
                    run.calls,
                    run.steps,
                    int(run.truncated),
                    run.answer,
                    json.dumps(run.context),
                ),
            )
            run_id = cursor.lastrowid
            if run_id is None:
                raise RuntimeError("insert did not return a row id")
            rows = [
                (
                    run_id,
                    seq,
                    event.step,
                    event.kind,
                    event.tool,
                    json.dumps([{"name": n, "value": v} for n, v in event.args]),
                    event.detail,
                )
                for seq, event in enumerate(run.events)
            ]
            self._conn.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        return run_id

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            event_rows = self._conn.execute(
                "SELECT * FROM events WHERE run_id = ? ORDER BY seq", (run_id,)
            ).fetchall()
        run = _summary(row)
        run["answer"] = row["answer"]
        run["context"] = json.loads(row["context_json"])
        run["events"] = [
            {
                "step": e["step"],
                "kind": e["kind"],
                "tool": e["tool"],
                "args": json.loads(e["args_json"]),
                "detail": e["detail"],
            }
            for e in event_rows
        ]
        return run

    def list_runs(
        self,
        *,
        defense: str | None = None,
        scenario_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if limit < 1 or offset < 0:
            raise ValueError("limit must be at least 1 and offset must not be negative")
        where, params = _where(defense, scenario_id)
        sql = f"SELECT {SUMMARY_COLUMNS} FROM runs{where} ORDER BY id DESC LIMIT ? OFFSET ?"
        with self._lock:
            rows = self._conn.execute(sql, [*params, limit, offset]).fetchall()
        return [_summary(row) for row in rows]

    def count_runs(self, *, defense: str | None = None, scenario_id: str | None = None) -> int:
        where, params = _where(defense, scenario_id)
        with self._lock:
            row = self._conn.execute(f"SELECT COUNT(*) FROM runs{where}", params).fetchone()
        return int(row[0])

    def delete_run(self, run_id: int) -> bool:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            return cursor.rowcount > 0

    def clear(self) -> int:
        with self._lock, self._conn:
            return self._conn.execute("DELETE FROM runs").rowcount

    def stats(self) -> list[dict[str, Any]]:
        """Per-defense totals over all stored runs."""
        sql = (
            "SELECT defense, COUNT(*) AS runs, SUM(is_attack) AS attacks, "
            "SUM(CASE WHEN is_attack = 1 AND attack_succeeded = 1 THEN 1 ELSE 0 END) "
            "AS attack_successes, SUM(1 - is_attack) AS benign, "
            "SUM(CASE WHEN is_attack = 0 AND utility_ok = 1 THEN 1 ELSE 0 END) AS benign_ok "
            "FROM runs GROUP BY defense ORDER BY defense"
        )
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        return [dict(row) for row in rows]
