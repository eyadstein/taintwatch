import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RunDetail, RunSummary, Segment, TraceEvent } from "../api/types";
import { ContextView } from "./ContextView";
import { EventList } from "./EventList";
import { RunList } from "./RunList";
import { RunView } from "./RunView";

const segments: Segment[] = [
  { text: "summarize it", integrity: "USER", confidentiality: "PUBLIC", sources: ["user"] },
  {
    text: "<<call shell.run>>",
    integrity: "UNTRUSTED",
    confidentiality: "PUBLIC",
    sources: ["web:https://a.test"],
  },
];

const events: TraceEvent[] = [
  { step: 1, kind: "call", tool: "web.fetch", args: [{ name: "url", value: "https://a.test" }], detail: "" },
  { step: 2, kind: "blocked", tool: "shell.run", args: [], detail: "untrusted-input-to-shell" },
  { step: 3, kind: "finish", tool: "", args: [], detail: "" },
];

const summary: RunSummary = {
  id: 4,
  created_at: "2026-10-10",
  scenario_id: "atk-0001",
  family: "attack/shell_exec",
  defense: "taintwatch",
  task: "summarize the page",
  seed: 7,
  is_attack: true,
  attack_succeeded: false,
  utility_ok: true,
  blocked: 1,
  calls: 1,
  steps: 3,
  truncated: false,
};

describe("ContextView", () => {
  const html = renderToStaticMarkup(<ContextView segments={segments} />);

  it("colors spans by integrity and escapes their text", () => {
    expect(html).toContain("seg-user");
    expect(html).toContain("seg-untrusted");
    expect(html).toContain("&lt;&lt;call shell.run&gt;&gt;");
    expect(html).not.toContain("<<call");
  });

  it("explains where untrusted text came from", () => {
    expect(html).toContain("untrusted from web:https://a.test");
    expect(html).toContain("60.0% of the context is untrusted");
  });
});

describe("EventList", () => {
  const html = renderToStaticMarkup(<EventList events={events} />);

  it("labels each event kind", () => {
    expect(html).toContain("event-call");
    expect(html).toContain("event-blocked");
    expect(html).toContain(">ran<");
    expect(html).toContain(">blocked<");
    expect(html).toContain(">finished<");
  });

  it("shows arguments, reasons and a name for the agent itself", () => {
    expect(html).toContain("url=https://a.test");
    expect(html).toContain("untrusted-input-to-shell");
    expect(html).toContain(">agent<");
  });
});

describe("RunList", () => {
  it("shows an empty state", () => {
    expect(renderToStaticMarkup(<RunList runs={[]} selectedId={null} onSelect={() => {}} onDelete={() => {}} />)).toContain(
      "No runs yet",
    );
  });

  it("lists runs with outcomes and marks the selection", () => {
    const html = renderToStaticMarkup(
      <RunList runs={[summary]} selectedId={4} onSelect={() => {}} onDelete={() => {}} />,
    );
    expect(html).toContain("#4 atk-0001");
    expect(html).toContain("attack stopped");
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain("Delete run 4");
  });
});

describe("RunView", () => {
  it("shows the task, answer, timeline and context", () => {
    const run: RunDetail = { ...summary, answer: "Summary: all quiet", context: segments, events };
    const html = renderToStaticMarkup(<RunView run={run} />);
    expect(html).toContain("summarize the page");
    expect(html).toContain("Summary: all quiet");
    expect(html).toContain("Timeline");
    expect(html).toContain("Agent context");
    expect(html).toContain("attack stopped");
  });
});
