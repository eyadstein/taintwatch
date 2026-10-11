import { Fragment } from "react";
import type { ScenarioDetail } from "../api/types";
import { INTEGRITY_LABEL } from "../lib/format";
import { describeCheck, familyLabel, formatPlanArgs, splitDirectives } from "../lib/scenario";

function Highlighted({ text }: { text: string }) {
  return (
    <pre className="source">
      {splitDirectives(text).map((part, index) =>
        part.directive ? (
          <mark key={index} className="directive">
            {part.text}
          </mark>
        ) : (
          <span key={index}>{part.text}</span>
        ),
      )}
    </pre>
  );
}

interface Props {
  scenario: ScenarioDetail;
}

export function ScenarioView({ scenario }: Props) {
  const meta = Object.entries(scenario.meta);
  return (
    <article className="scenario-view">
      <header className="card">
        <h2>
          {scenario.id} <span className="chip">{familyLabel(scenario.family)}</span>
        </h2>
        <p className="task">
          <strong>Task:</strong> {scenario.task}
        </p>
        {meta.length > 0 && (
          <dl className="facts">
            {meta.map(([key, value]) => (
              <Fragment key={key}>
                <dt>{key}</dt>
                <dd>{value}</dd>
              </Fragment>
            ))}
          </dl>
        )}
      </header>
      {scenario.web.map((page) => (
        <section key={page.url} className="card" aria-label="Web page">
          <h3>{`Web page ${page.url}`}</h3>
          <Highlighted text={page.text} />
        </section>
      ))}
      {scenario.inbox.map((text, index) => (
        <section key={index} className="card" aria-label="Inbox message">
          <h3>{`Inbox message ${index}`}</h3>
          <Highlighted text={text} />
        </section>
      ))}
      {scenario.files.map((file) => (
        <section key={file.path} className="card" aria-label="File">
          <h3>{`File ${file.path}`}</h3>
          <p className="muted">
            {`${INTEGRITY_LABEL[file.integrity]} integrity, ${file.confidentiality.toLowerCase()}`}
          </p>
          <Highlighted text={file.content} />
        </section>
      ))}
      <section className="card" aria-label="Agent plan">
        <h3>Agent plan</h3>
        <ol className="plan">
          {scenario.plan.map((step, index) => (
            <li key={index}>
              <code>{step.tool}</code> {formatPlanArgs(step.args)}
            </li>
          ))}
        </ol>
        <p className="muted">{`Answer template: ${scenario.answer}`}</p>
      </section>
      <section className="card" aria-label="Success checks">
        <h3>Success checks</h3>
        {scenario.attack && <p>{`Attack succeeds if ${describeCheck(scenario.attack)}.`}</p>}
        {scenario.utility && <p>{`Task succeeds if ${describeCheck(scenario.utility)}.`}</p>}
      </section>
    </article>
  );
}
