import type { RunSummary } from "../api/types";
import { describeOutcome } from "../lib/format";

interface Props {
  runs: readonly RunSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onDelete: (id: number) => void;
}

export function RunList({ runs, selectedId, onSelect, onDelete }: Props) {
  if (runs.length === 0) {
    return <p className="empty">No runs yet. Pick a scenario above and run it.</p>;
  }
  return (
    <ul className="runs">
      {runs.map((run) => {
        const outcome = describeOutcome(run);
        const selected = run.id === selectedId;
        return (
          <li key={run.id}>
            <button
              type="button"
              className={selected ? "run selected" : "run"}
              aria-pressed={selected}
              onClick={() => onSelect(run.id)}
            >
              <span className="run-title">
                #{run.id} {run.scenario_id}
              </span>
              <span className="run-defense">{run.defense}</span>
              <span className={`tone tone-${outcome.tone}`}>{outcome.label}</span>
            </button>
            <button
              type="button"
              className="delete"
              aria-label={`Delete run ${run.id}`}
              onClick={() => onDelete(run.id)}
            >
              Delete
            </button>
          </li>
        );
      })}
    </ul>
  );
}
