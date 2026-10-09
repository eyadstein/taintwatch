# Agent runtime

`taintwatch.agent` runs an agent loop where every tool argument passes through `Guard`.

- `ToolRegistry` / `Tool`: tools are named `namespace.action` and declare their parameters.
- `World`: simulated files, web pages, inbox, sent mail, HTTP requests and shell history.
  Effects are recorded only when a tool actually runs, so a blocked attack leaves no trace.
- `build_standard_registry(world)`: `web.fetch`, `email.inbox`, `email.send`, `fs.read`,
  `fs.write`, `http.post`, `shell.run`. Each tool declares the integrity and confidentiality
  of its output. Fetched pages, inbox mail and HTTP responses are `UNTRUSTED`.
- `AgentRuntime.run(agent, task)`: loops until the agent finishes or `max_steps` is hit.
  Blocked calls, unknown tools and bad arguments come back to the agent as observations.
  The result holds an event trace, the final answer and the full labeled context.
- `ScriptedAgent`: follows a plan of `PlanStep`s. When `gullible=True` it also obeys
  directives (`<<call tool key="value">>`) found in successful tool output. That is a
  worst-case model of an LLM that follows injected instructions; arguments are slices of the
  tainted text, so they keep their span labels. `{rN}` placeholders in injected arguments are
  filled with earlier results, which is how an injection can pull a secret into a call.

Limits:
- The mock agent is not an LLM. Results show what the policy layer catches against a
  maximally compliant attacker model, not how often real models are fooled.
- Files written by the agent are stored as `UNTRUSTED` so taint cannot be laundered through
  the filesystem. This is conservative.
