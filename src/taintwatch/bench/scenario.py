"""Benchmark scenario data model: a task, a world, a plan and what counts as success."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from taintwatch.agent import FileEntry, PlanStep, ScriptedAgent, World
from taintwatch.labels import Confidentiality, Integrity


class Effect(StrEnum):
    COMMAND_RAN = "command_ran"
    SECRET_LEAKED = "secret_leaked"
    EMAIL_TO = "email_to"
    FILE_WRITTEN = "file_written"
    ANSWER_HAS = "answer_has"


@dataclass(frozen=True, slots=True)
class Check:
    """A machine-checkable outcome, evaluated against the world after a run."""

    effect: Effect
    value: str

    def holds(self, world: World, answer: str = "") -> bool:
        if self.effect is Effect.COMMAND_RAN:
            return any(self.value in command for command in world.commands)
        if self.effect is Effect.SECRET_LEAKED:
            return world.leaked(self.value)
        if self.effect is Effect.EMAIL_TO:
            return any(mail.to == self.value for mail in world.sent)
        if self.effect is Effect.FILE_WRITTEN:
            return any(path == self.value for path, _ in world.writes)
        return self.value in answer

    def to_dict(self) -> dict[str, str]:
        return {"effect": self.effect.value, "value": self.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, str]) -> Check:
        return cls(Effect(data["effect"]), data["value"])


Meta = tuple[tuple[str, str], ...]


def make_meta(**items: str) -> Meta:
    """Sorted key/value tags describing how a scenario was generated."""
    return tuple(sorted(items.items()))


def _file_to_dict(entry: FileEntry) -> dict[str, str]:
    return {
        "content": entry.content,
        "integrity": entry.integrity.name,
        "confidentiality": entry.confidentiality.name,
    }


def _file_from_dict(data: Mapping[str, str]) -> FileEntry:
    return FileEntry(
        data["content"],
        Integrity[data["integrity"]],
        Confidentiality[data["confidentiality"]],
    )


@dataclass(frozen=True, slots=True)
class Scenario:
    id: str
    family: str
    task: str
    plan: tuple[PlanStep, ...]
    answer: str
    web: tuple[tuple[str, str], ...] = ()
    inbox: tuple[str, ...] = ()
    files: tuple[tuple[str, FileEntry], ...] = ()
    attack: Check | None = None
    utility: Check | None = None
    meta: Meta = ()

    @property
    def is_attack(self) -> bool:
        return self.attack is not None

    def meta_value(self, key: str, default: str = "") -> str:
        return dict(self.meta).get(key, default)

    def build_world(self) -> World:
        """A fresh world, so runs never share state."""
        return World(web=dict(self.web), inbox=list(self.inbox), files=dict(self.files))

    def build_agent(self, *, gullible: bool = True) -> ScriptedAgent:
        return ScriptedAgent(self.plan, gullible=gullible, answer=self.answer)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "family": self.family,
            "task": self.task,
            "plan": [{"tool": s.tool, "args": dict(s.args)} for s in self.plan],
            "answer": self.answer,
            "web": [[url, text] for url, text in self.web],
            "inbox": list(self.inbox),
            "files": [[path, _file_to_dict(entry)] for path, entry in self.files],
            "attack": None if self.attack is None else self.attack.to_dict(),
            "utility": None if self.utility is None else self.utility.to_dict(),
            "meta": dict(self.meta),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Scenario:
        attack = data["attack"]
        utility = data["utility"]
        return cls(
            id=data["id"],
            family=data["family"],
            task=data["task"],
            plan=tuple(PlanStep(s["tool"], dict(s["args"])) for s in data["plan"]),
            answer=data["answer"],
            web=tuple((url, text) for url, text in data["web"]),
            inbox=tuple(data["inbox"]),
            files=tuple((path, _file_from_dict(entry)) for path, entry in data["files"]),
            attack=None if attack is None else Check.from_dict(attack),
            utility=None if utility is None else Check.from_dict(utility),
            meta=tuple(sorted((str(k), str(v)) for k, v in data["meta"].items())),
        )
