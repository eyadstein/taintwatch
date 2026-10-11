import type { RateGroups } from "../api/types";
import { percent } from "../lib/format";
import { rateTone, unionKeys } from "../lib/results";

interface Props {
  title: string;
  groups: RateGroups;
  goodWhenHigh: boolean;
  labelOf?: (key: string) => string;
}

export function BreakdownTable({ title, groups, goodWhenHigh, labelOf }: Props) {
  const columns = unionKeys(groups);
  const label = labelOf ?? ((key: string) => key);
  return (
    <section className="card" aria-label={title}>
      <h3>{title}</h3>
      <div className="table-scroll">
        <table className="data">
          <thead>
            <tr>
              <th scope="col">defense</th>
              {columns.map((column) => (
                <th key={column} scope="col">
                  {label(column)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Object.keys(groups).map((defense) => (
              <tr key={defense}>
                <th scope="row">{defense}</th>
                {columns.map((column) => {
                  const cell = groups[defense]?.[column];
                  return cell ? (
                    <td key={column} className={`cell cell-${rateTone(cell.rate, goodWhenHigh)}`}>
                      {percent(cell.rate)}
                    </td>
                  ) : (
                    <td key={column}>n/a</td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
