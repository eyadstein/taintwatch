import { useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { DefenseInfo, RunDetail, ScenarioSummary } from "../api/types";

type Kind = "attack" | "benign";

interface Props {
  onCreated: (run: RunDetail) => void;
  onError: (message: string) => void;
}

export function RunForm({ onCreated, onError }: Props) {
  const [kind, setKind] = useState<Kind>("attack");
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([]);
  const [defenses, setDefenses] = useState<DefenseInfo[]>([]);
  const [scenarioId, setScenarioId] = useState("");
  const [defense, setDefense] = useState("taintwatch");
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    api
      .defenses()
      .then((items) => {
        if (active) setDefenses(items);
      })
      .catch((error: unknown) => onError(errorMessage(error)));
    return () => {
      active = false;
    };
  }, [onError]);

  useEffect(() => {
    let active = true;
    api
      .scenarios({ attack: kind === "attack", limit: 500 })
      .then((page) => {
        if (!active) return;
        setScenarios(page.items);
        setScenarioId(page.items[0]?.id ?? "");
      })
      .catch((error: unknown) => onError(errorMessage(error)));
    return () => {
      active = false;
    };
  }, [kind, onError]);

  async function submit() {
    if (!scenarioId) return;
    setBusy(true);
    try {
      onCreated(await api.createRun({ scenario_id: scenarioId, defense, confirm }));
    } catch (error) {
      onError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-label="Run a scenario">
      <h2>Run a scenario</h2>
      <label>
        Type
        <select value={kind} onChange={(event) => setKind(event.target.value as Kind)}>
          <option value="attack">Attack</option>
          <option value="benign">Benign task</option>
        </select>
      </label>
      <label>
        Scenario
        <select value={scenarioId} onChange={(event) => setScenarioId(event.target.value)}>
          {scenarios.map((scenario) => (
            <option key={scenario.id} value={scenario.id}>
              {scenario.id} ({scenario.family.split("/").pop()})
            </option>
          ))}
        </select>
      </label>
      <label>
        Defense
        <select value={defense} onChange={(event) => setDefense(event.target.value)}>
          {defenses.map((item) => (
            <option key={item.spec} value={item.spec} title={item.description}>
              {item.name}
            </option>
          ))}
        </select>
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={confirm}
          onChange={(event) => setConfirm(event.target.checked)}
        />
        Auto-approve confirmation prompts
      </label>
      <button type="button" className="primary" disabled={busy || !scenarioId} onClick={() => void submit()}>
        {busy ? "Running..." : "Run"}
      </button>
    </section>
  );
}
