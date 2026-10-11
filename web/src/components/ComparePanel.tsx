import { useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { DefenseInfo, RunDetail } from "../api/types";
import { CompareView } from "./CompareView";

interface Props {
  scenarioId: string;
  onError: (message: string) => void;
  onChanged: () => void;
}

export function ComparePanel({ scenarioId, onError, onChanged }: Props) {
  const [defenses, setDefenses] = useState<DefenseInfo[]>([]);
  const [first, setFirst] = useState("none");
  const [second, setSecond] = useState("taintwatch");
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<[RunDetail, RunDetail] | null>(null);

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
    setResult(null);
  }, [scenarioId]);

  async function submit() {
    setBusy(true);
    try {
      const [a, b] = await Promise.all([
        api.createRun({ scenario_id: scenarioId, defense: first, confirm }),
        api.createRun({ scenario_id: scenarioId, defense: second, confirm }),
      ]);
      setResult([a, b]);
      onChanged();
    } catch (error) {
      onError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="card" aria-label="Compare defenses">
        <h2>Compare two defenses</h2>
        <label>
          First defense
          <select value={first} onChange={(event) => setFirst(event.target.value)}>
            {defenses.map((item) => (
              <option key={item.spec} value={item.spec} title={item.description}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Second defense
          <select value={second} onChange={(event) => setSecond(event.target.value)}>
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
        <button type="button" className="primary" disabled={busy} onClick={() => void submit()}>
          {busy ? "Running..." : "Run both"}
        </button>
      </section>
      {result && <CompareView a={result[0]} b={result[1]} />}
    </>
  );
}
