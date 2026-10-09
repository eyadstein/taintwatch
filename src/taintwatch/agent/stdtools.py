"""The standard tool set, bound to a simulated ``World``."""

from __future__ import annotations

from taintwatch.agent.tools import Tool, ToolOutput, ToolRegistry
from taintwatch.agent.world import FileEntry, HttpRequest, SentEmail, World
from taintwatch.labels import Integrity


def build_standard_registry(world: World) -> ToolRegistry:
    def web_fetch(url: str) -> ToolOutput:
        body = world.web.get(url, "[404 not found]")
        return ToolOutput(body, Integrity.UNTRUSTED, source=f"web:{url}")

    def email_inbox(index: str) -> ToolOutput:
        try:
            position = int(index)
        except ValueError:
            return ToolOutput("[invalid index]", Integrity.SYSTEM)
        if not 0 <= position < len(world.inbox):
            return ToolOutput("[no such message]", Integrity.SYSTEM)
        return ToolOutput(world.inbox[position], Integrity.UNTRUSTED, source=f"email:{position}")

    def email_send(to: str, body: str) -> ToolOutput:
        world.sent.append(SentEmail(to, body))
        return ToolOutput("sent", Integrity.SYSTEM)

    def fs_read(path: str) -> ToolOutput:
        entry = world.files.get(path)
        if entry is None:
            return ToolOutput("[no such file]", Integrity.SYSTEM)
        return ToolOutput(
            entry.content, entry.integrity, entry.confidentiality, source=f"file:{path}"
        )

    def fs_write(path: str, content: str) -> ToolOutput:
        # Conservative: agent-written files are stored untrusted so taint cannot be laundered.
        world.files[path] = FileEntry(content, Integrity.UNTRUSTED)
        world.writes.append((path, content))
        return ToolOutput("written", Integrity.SYSTEM)

    def http_post(url: str, data: str) -> ToolOutput:
        world.requests.append(HttpRequest(url, data))
        return ToolOutput("200 OK", Integrity.UNTRUSTED, source=f"http:{url}")

    def shell_run(cmd: str) -> ToolOutput:
        world.commands.append(cmd)
        return ToolOutput(f"$ {cmd}\n(exit 0)", Integrity.TOOL_OUTPUT, source="shell")

    return ToolRegistry(
        [
            Tool("web.fetch", ("url",), web_fetch, "Fetch a web page."),
            Tool("email.inbox", ("index",), email_inbox, "Read an inbox message."),
            Tool("email.send", ("to", "body"), email_send, "Send an email."),
            Tool("fs.read", ("path",), fs_read, "Read a file."),
            Tool("fs.write", ("path", "content"), fs_write, "Write a file."),
            Tool("http.post", ("url", "data"), http_post, "POST data to a URL."),
            Tool("shell.run", ("cmd",), shell_run, "Run a shell command."),
        ]
    )
