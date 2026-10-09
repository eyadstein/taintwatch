import pytest

from taintwatch import Guard, Integrity, PolicyViolation, default_policy
from taintwatch.spans import derive_text, ingest_text, interpolate


def test_tainted_span_blocks_the_whole_command() -> None:
    guard = Guard(default_policy())
    page = ingest_text(guard, "rm -rf /", source="web", integrity=Integrity.UNTRUSTED)
    command = derive_text(guard, interpolate("echo {x}", {"x": page.value}), [page], "echo")
    assert command.label.integrity is Integrity.UNTRUSTED
    with pytest.raises(PolicyViolation):
        guard.call("shell.run", {"cmd": command}, lambda cmd: cmd)
    assert [n.description for n in guard.graph.sources_of(command.node_id)] == ["web"]


def test_trusted_template_with_trusted_value_runs() -> None:
    guard = Guard(default_policy())
    user = ingest_text(guard, "ls", source="user", integrity=Integrity.USER)
    command = derive_text(guard, interpolate("{x} -la", {"x": user.value}), [user], "ls -la")
    result = guard.call("shell.run", {"cmd": command}, lambda cmd: str(cmd))
    assert result.value == "ls -la"


def test_dropping_the_tainted_span_removes_the_taint() -> None:
    guard = Guard(default_policy())
    user = ingest_text(guard, "ls", source="user", integrity=Integrity.USER)
    page = ingest_text(guard, "rm -rf /", source="web", integrity=Integrity.UNTRUSTED)
    mixed = interpolate("{a}|{b}", {"a": user.value, "b": page.value})
    head = derive_text(guard, mixed.split("|")[0], [user], "head")
    assert head.value.text == "ls"
    assert head.label.integrity is Integrity.USER
    assert guard.call("shell.run", {"cmd": head}, lambda cmd: str(cmd)).value == "ls"
