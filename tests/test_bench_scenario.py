import json

from taintwatch.agent import FileEntry, SentEmail, World
from taintwatch.bench import (
    Check,
    Effect,
    Scenario,
    generate_attacks,
    generate_benign,
    make_meta,
)
from taintwatch.labels import Confidentiality, Integrity


def test_check_effects() -> None:
    world = World()
    world.commands.append("rm -rf /tmp/x")
    world.sent.append(SentEmail("a@b.c", "token-123"))
    world.writes.append(("/etc/job", "data"))
    assert Check(Effect.COMMAND_RAN, "rm -rf").holds(world)
    assert not Check(Effect.COMMAND_RAN, "curl").holds(world)
    assert Check(Effect.SECRET_LEAKED, "token-123").holds(world)
    assert not Check(Effect.SECRET_LEAKED, "other").holds(world)
    assert Check(Effect.EMAIL_TO, "a@b.c").holds(world)
    assert not Check(Effect.EMAIL_TO, "x@y.z").holds(world)
    assert Check(Effect.FILE_WRITTEN, "/etc/job").holds(world)
    assert not Check(Effect.FILE_WRITTEN, "/etc/other").holds(world)
    assert Check(Effect.ANSWER_HAS, "hello").holds(world, "say hello there")
    assert not Check(Effect.ANSWER_HAS, "hello").holds(world, "bye")


def test_make_meta_is_sorted() -> None:
    assert make_meta(b="2", a="1") == (("a", "1"), ("b", "2"))


def test_dict_roundtrip_for_attacks_and_benign() -> None:
    scenarios = [*generate_attacks(40), *generate_benign(21)]
    for scenario in scenarios:
        encoded = json.dumps(scenario.to_dict(), sort_keys=True)
        assert Scenario.from_dict(json.loads(encoded)) == scenario


def test_roundtrip_keeps_file_labels() -> None:
    entry = FileEntry("v", Integrity.SYSTEM, Confidentiality.SECRET)
    scenario = Scenario("s", "f", "t", (), "a", files=(("/k", entry),))
    restored = Scenario.from_dict(json.loads(json.dumps(scenario.to_dict())))
    assert restored.files == (("/k", entry),)


def test_build_world_is_fresh_every_time() -> None:
    scenario = generate_attacks(1)[0]
    first = scenario.build_world()
    first.web["x"] = "y"
    first.commands.append("ls")
    second = scenario.build_world()
    assert "x" not in second.web
    assert second.commands == []


def test_scenario_flags_and_meta_lookup() -> None:
    attack = generate_attacks(1)[0]
    benign = generate_benign(1)[0]
    assert attack.is_attack
    assert not benign.is_attack
    assert attack.meta_value("goal") != ""
    assert attack.meta_value("nope", "dflt") == "dflt"
