import type { ResultsData } from "../api/types";
import { percent } from "../lib/format";
import {
  RESULT_NOTES,
  formatInterval,
  formatOverhead,
  formatP,
} from "../lib/results";
import { familyLabel } from "../lib/scenario";
import { BreakdownTable } from "./BreakdownTable";
import { RateBars } from "./RateBars";

interface Props {
  data: ResultsData;
}

export function ResultsDashboard({ data }: Props) {
  const first = data.defenses[0];
  const attackRows = data.defenses.map((d) => ({ label: d.defense, rate: d.attack_success }));
  const benignRows = data.defenses.map((d) => ({ label: d.defense, rate: d.benign_utility }));
  return (
    <div className="results">
      <section className="card" aria-label="Overall results">
        <h2>Benchmark results</h2>
        <p className="muted">
          {first
            ? `${first.attack_success.total} attacks and ${first.benign_utility.total} benign tasks per defense. Whiskers and brackets are 95% Wilson intervals.`
            : "No results."}
        </p>
        <div className="table-scroll">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">defense</th>
                <th scope="col">attack success</th>
                <th scope="col">benign utility</th>
                <th scope="col">utility under attack</th>
                <th scope="col">benign policy blocks</th>
                <th scope="col">overhead</th>
              </tr>
            </thead>
            <tbody>
              {data.defenses.map((d) => (
                <tr key={d.defense}>
                  <th scope="row">{d.defense}</th>
                  <td>{`${percent(d.attack_success.rate)} ${formatInterval(d.attack_success)}`}</td>
                  <td>{percent(d.benign_utility.rate)}</td>
                  <td>{percent(d.utility_under_attack.rate)}</td>
                  <td>{percent(d.benign_blocked.rate)}</td>
                  <td>{formatOverhead(d.overhead)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <RateBars title="Attack success (lower is better)" rows={attackRows} tone="bad" />
      <RateBars title="Benign utility (higher is better)" rows={benignRows} tone="good" />
      {Object.entries(data.attack_breakdown).map(([key, groups]) => (
        <BreakdownTable
          key={key}
          title={`Attack success by ${key}`}
          groups={groups}
          goodWhenHigh={false}
        />
      ))}
      <BreakdownTable
        title="Benign utility by family"
        groups={data.benign_breakdown}
        goodWhenHigh
        labelOf={familyLabel}
      />
      <section className="card" aria-label="Paired comparison">
        <h3>{`Paired comparison against ${data.pivot}`}</h3>
        <div className="table-scroll">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">defense</th>
                <th scope="col">attacks that succeed only against it</th>
                <th scope="col">{`attacks that succeed only against ${data.pivot}`}</th>
                <th scope="col">exact McNemar p</th>
              </tr>
            </thead>
            <tbody>
              {data.paired.map((p) => (
                <tr key={p.defense}>
                  <th scope="row">{p.defense}</th>
                  <td>{p.only_defense_succeeds}</td>
                  <td>{p.only_pivot_succeeds}</td>
                  <td>{formatP(p.mcnemar_p)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="card" aria-label="Notes">
        <h3>Notes</h3>
        <ul>
          {RESULT_NOTES.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
