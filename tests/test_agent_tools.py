from pathlib import Path

import pytest

from taintwatch.agent import (
    Tool,
    ToolArgumentError,
    ToolError,
    ToolOutput,
    ToolRegistry,
    UnknownToolError,
    World,
    build_standard_registry,
)
from taintwatch.agent.world import FileEntry, HttpRequest, SentEmail
from taintwatch.dsl import lint
from taintwatch.labels import Confidentiality, Integrity

DEFAULT_FILE = Path(__file__).resolve().parents[1] / "policies" / "default.twp"


def echo(msg: str) -> ToolOutput:
    return ToolOutput(msg)


def test_register_and_lookup() -> None:
    registry = ToolRegistry([Tool("a.echo", ("msg",), echo)])
    assert "a.echo" in registry
    assert len(registry) == 1
    assert registry.get("a.echo").invoke({"msg": "hi"}).text == "hi"
    assert registry.find("nope.x") is None
    assert [t.name for t in registry] == ["a.echo"]
    with pytest.raises(UnknownToolError):
        registry.get("nope.x")


def test_duplicate_is_rejected() -> None:
    registry = ToolRegistry([Tool("a.echo", ("msg",), echo)])
    with pytest.raises(ToolError, match="already registered"):
        registry.register(Tool("a.echo", ("msg",), echo))


@pytest.mark.parametrize("name", ["echo", "Bad.name", "a.b.c", "a.", ".b", "a b.c"])
def test_invalid_names_are_rejected(name: str) -> None:
    with pytest.raises(ToolError, match="invalid tool name"):
        ToolRegistry([Tool(name, ("msg",), echo)])


def test_argument_checking() -> None:
    tool = Tool("a.echo", ("msg",), echo)
    with pytest.raises(ToolArgumentError, match="missing"):
        tool.invoke({})
    with pytest.raises(ToolArgumentError, match="unexpected"):
        tool.invoke({"msg": "x", "other": "y"})


def test_names_are_sorted() -> None:
    registry = ToolRegistry([Tool("b.x", (), echo), Tool("a.x", (), echo)])
    assert registry.names() == ("a.x", "b.x")


def test_standard_tool_names() -> None:
    names = build_standard_registry(World()).names()
    assert names == (
        "email.inbox",
        "email.send",
        "fs.read",
        "fs.write",
        "http.post",
        "shell.run",
        "web.fetch",
    )


def test_web_fetch_is_untrusted() -> None:
    world = World(web={"https://a.test": "page"})
    tool = build_standard_registry(world).get("web.fetch")
    out = tool.invoke({"url": "https://a.test"})
    assert (out.text, out.integrity) == ("page", Integrity.UNTRUSTED)
    assert tool.invoke({"url": "https://nope.test"}).text == "[404 not found]"


def test_inbox_messages() -> None:
    tool = build_standard_registry(World(inbox=["mail one"])).get("email.inbox")
    first = tool.invoke({"index": "0"})
    assert (first.text, first.integrity) == ("mail one", Integrity.UNTRUSTED)
    assert tool.invoke({"index": "7"}).text == "[no such message]"
    assert tool.invoke({"index": "x"}).text == "[invalid index]"


def test_fs_read_uses_the_file_label() -> None:
    world = World(files={"/k": FileEntry("v", Integrity.SYSTEM, Confidentiality.SECRET)})
    tool = build_standard_registry(world).get("fs.read")
    out = tool.invoke({"path": "/k"})
    assert (out.integrity, out.confidentiality) == (Integrity.SYSTEM, Confidentiality.SECRET)
    assert tool.invoke({"path": "/missing"}).text == "[no such file]"


def test_side_effects_are_recorded() -> None:
    world = World()
    registry = build_standard_registry(world)
    registry.get("email.send").invoke({"to": "a@b.c", "body": "hi"})
    registry.get("http.post").invoke({"url": "https://x.test", "data": "d"})
    registry.get("shell.run").invoke({"cmd": "ls"})
    registry.get("fs.write").invoke({"path": "/x", "content": "data"})
    assert world.sent == [SentEmail("a@b.c", "hi")]
    assert world.requests == [HttpRequest("https://x.test", "d")]
    assert world.commands == ["ls"]
    assert world.writes == [("/x", "data")]
    assert world.files["/x"].integrity is Integrity.UNTRUSTED


def test_leaked_detects_email_and_http() -> None:
    world = World()
    registry = build_standard_registry(world)
    assert not world.leaked("s3cret")
    registry.get("http.post").invoke({"url": "https://x.test", "data": "s3cret"})
    assert world.leaked("s3cret")
    other = World()
    build_standard_registry(other).get("email.send").invoke({"to": "a@b.c", "body": "s3cret"})
    assert other.leaked("s3cret")


def test_default_policy_leaves_read_only_tools_uncovered() -> None:
    text = DEFAULT_FILE.read_text(encoding="utf-8")
    names = build_standard_registry(World()).names()
    messages = {d.message for d in lint(text, names)}
    assert messages == {
        "known tool 'email.inbox' has no rule",
        "known tool 'fs.read' has no rule",
        "known tool 'web.fetch' has no rule",
    }
