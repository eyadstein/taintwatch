import type { RunDetail } from "../api/types";
import { compareRows } from "../lib/scenario";
import { RunView } from "./RunView";

interface Props {
  a: RunDetail;
  b: RunDetail;
}

export function CompareView({ a, b }: Props) {
  const rows = compareRows(a, b);
  return (
    <section aria-label="Defense comparison">
      <div className="card">
        <h2>Comparison</h2>
        <table className="diff">
          <thead>
            <tr>
              <th scope="col">Measure</th>
              <th scope="col">{a.defense}</th>
              <th scope="col">{b.defense}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.label} className={row.differs ? "differs" : undefined}>
                <th scope="row">{row.label}</th>
                <td>{row.a}</td>
                <td>{row.b}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted">Rows in bold differ between the two defenses.</p>
      </div>
      <div className="compare">
        <RunView run={a} />
        <RunView run={b} />
      </div>
    </section>
  );
}
