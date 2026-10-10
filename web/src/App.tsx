import { useCallback, useEffect, useState } from "react";
import { api, errorMessage } from "./api/client";
import type { HealthInfo, Page, RunDetail, RunSummary } from "./api/types";
import { RunForm } from "./components/RunForm";
import { RunList } from "./components/RunList";
import { RunView } from "./components/RunView";

export default function App() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [runs, setRuns] = useState<Page<RunSummary>>({ total: 0, items: [] });
  const [selected, setSelected] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [info, page] = await Promise.all([api.health(), api.listRuns({ limit: 100 })]);
      setHealth(info);
      setRuns(page);
      setError(null);
    } catch (problem) {
      setError(errorMessage(problem));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const open = useCallback(async (id: number) => {
    try {
      setSelected(await api.getRun(id));
      setError(null);
    } catch (problem) {
      setError(errorMessage(problem));
    }
  }, []);

  const remove = useCallback(
    async (id: number) => {
      try {
        await api.deleteRun(id);
        setSelected((current) => (current?.id === id ? null : current));
        await refresh();
      } catch (problem) {
        setError(errorMessage(problem));
      }
    },
    [refresh],
  );

  const created = useCallback(
    (run: RunDetail) => {
      setSelected(run);
      void refresh();
    },
    [refresh],
  );

  return (
    <div className="app">
      <header className="top">
        <h1>Taintwatch</h1>
        <p className="muted">Trace viewer for information-flow control on LLM agent runs</p>
        <p className="muted" role="status">
          {health
            ? `${health.scenarios} scenarios, ${health.runs} stored runs`
            : "Connecting to the API..."}
        </p>
      </header>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="layout">
        <aside>
          <RunForm onCreated={created} onError={setError} />
          <h2>Runs ({runs.total})</h2>
          <RunList
            runs={runs.items}
            selectedId={selected?.id ?? null}
            onSelect={(id) => void open(id)}
            onDelete={(id) => void remove(id)}
          />
        </aside>
        <main>
          {selected ? (
            <RunView run={selected} />
          ) : (
            <p className="empty">Select a run or start a new one.</p>
          )}
        </main>
      </div>
    </div>
  );
}
