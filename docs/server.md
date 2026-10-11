# Server

    pip install -e ".[dev,server]"
    python -m taintwatch.server              # http://127.0.0.1:8000, docs at /docs
    python -m taintwatch.server --db runs.db --port 9000

| Method and path | Purpose |
|---|---|
| `GET /api/health` | Status, scenario count, stored run count. |
| `GET /api/defenses` | The default defense specs with descriptions. |
| `GET /api/scenarios` | List scenarios. Query: `family`, `attack`, `limit`, `offset`. |
| `GET /api/scenarios/{id}` | Full scenario: plan, pages, inbox, files, success checks. |
| `POST /api/runs` | Body `{scenario_id, defense, seed, confirm}`. Runs and stores a trace. |
| `GET /api/runs` | List stored runs. Query: `defense`, `scenario_id`, `limit`, `offset`. |
| `GET /api/runs/{id}` | One run with its events and the labeled context as segments. |
| `DELETE /api/runs/{id}` | Remove a stored run. |
| `GET /api/stats` | Per-defense totals and rates over stored runs. |

A run's `context` is a list of `{text, integrity, confidentiality, sources}` segments, so a
viewer can color each span of the agent's context by its trust level.

## Limits

- No authentication or rate limiting. Run it locally only.
- It drives the mock agent, not a real model.
- CORS allows the Vite dev server on port 5173 only.
| `GET /api/families` | Scenario families with their counts and whether they are attacks. |
