# Trace viewer

    npm --prefix web install
    python -m taintwatch.server        # terminal 1: API on http://127.0.0.1:8000
    npm --prefix web run dev           # terminal 2: viewer on http://localhost:5173

Vite proxies `/api` to the Python server, so no CORS setup is needed in development.

- Pick an attack or benign scenario, a defense, and run it. The run is stored in SQLite.
- The context view colors each span of the agent's context by integrity. Untrusted spans also
  get a wavy underline, so the signal does not rely on color. Hover a span for its sources.
- The timeline lists every tool call as ran, blocked or error, with the policy reason.

Checks: `npm --prefix web run typecheck`, `npm --prefix web test`, `npm --prefix web run build`.

Limits: scenarios load 500 at a time, so the launcher is not a full scenario browser.

## Scenario browser and comparison (Part 10)

The **Scenarios** tab pages through every scenario, 25 at a time, filtered by type and family.
A scenario shows its task, the web pages, inbox messages and files the agent reads (injected
`<<call ...>>` directives are highlighted), the agent's plan, and the success checks in plain
English. "Compare two defenses" runs the same scenario under two defenses with the same seed and
shows a difference table plus both traces side by side. Both runs are stored and appear in the
Runs tab.

Directive highlighting is a pattern match on the mock agent's attack format, not a general
injection detector.
