import type { RunDetail } from "../api/types";
import { describeOutcome } from "../lib/format";
import { ContextView } from "./ContextView";
import { EventList } from "./EventList";

interface Props {
  run: RunDetail;
}

export function RunView({ run }: Props) {
  const outcome = describeOutcome(run);
  return (
    <article className="run-view">
      <header className="card">
        <h2>
          Run #{run.id} <span className={`tone tone-${outcome.tone}`}>{outcome.label}</span>
        </h2>
        <dl className="facts">
          <dt>Scenario</dt>
          <dd>{run.scenario_id}</dd>
          <dt>Defense</dt>
          <dd>{run.defense}</dd>
          <dt>Blocked calls</dt>
          <dd>{run.blocked}</dd>
          <dt>Tool calls</dt>
          <dd>{run.calls}</dd>
          <dt>Steps</dt>
          <dd>{run.steps}</dd>
        </dl>
        <p className="task">
          <strong>Task:</strong> {run.task}
        </p>
      </header>
      <EventList events={run.events} />
      <ContextView segments={run.context} />
      <section aria-label="Final answer" className="card">
        <h3>Final answer</h3>
        <pre className="answer">{run.answer}</pre>
      </section>
    </article>
  );
}
