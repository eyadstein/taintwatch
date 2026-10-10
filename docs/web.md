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
