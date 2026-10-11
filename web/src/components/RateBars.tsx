import type { RateInfo } from "../api/types";
import { formatRate } from "../lib/results";

export interface BarRow {
  label: string;
  rate: RateInfo;
}

interface Props {
  title: string;
  rows: readonly BarRow[];
  tone: "bad" | "good";
}

const LABEL_W = 150;
const BAR_W = 300;
const VALUE_W = 140;
const ROW_H = 28;
const PAD = 6;
const WIDTH = LABEL_W + BAR_W + VALUE_W;

export function RateBars({ title, rows, tone }: Props) {
  const height = rows.length * ROW_H + PAD * 2;
  return (
    <figure className="card chart-card">
      <figcaption>{title}</figcaption>
      <svg viewBox={`0 0 ${WIDTH} ${height}`} role="img" aria-label={title} className="chart">
        {rows.map((row, index) => {
          const top = PAD + index * ROW_H;
          const mid = top + ROW_H / 2;
          const low = LABEL_W + row.rate.lo * BAR_W;
          const high = LABEL_W + row.rate.hi * BAR_W;
          return (
            <g key={row.label}>
              <text x={0} y={mid} dominantBaseline="middle" className="chart-label">
                {row.label}
              </text>
              <rect x={LABEL_W} y={top + 6} width={BAR_W} height={ROW_H - 12} className="chart-track" />
              <rect
                x={LABEL_W}
                y={top + 6}
                width={row.rate.rate * BAR_W}
                height={ROW_H - 12}
                className={`chart-bar chart-${tone}`}
              />
              <line x1={low} x2={high} y1={mid} y2={mid} className="chart-ci" />
              <line x1={low} x2={low} y1={mid - 5} y2={mid + 5} className="chart-ci" />
              <line x1={high} x2={high} y1={mid - 5} y2={mid + 5} className="chart-ci" />
              <text x={LABEL_W + BAR_W + 8} y={mid} dominantBaseline="middle" className="chart-value">
                {formatRate(row.rate)}
              </text>
            </g>
          );
        })}
      </svg>
    </figure>
  );
}
