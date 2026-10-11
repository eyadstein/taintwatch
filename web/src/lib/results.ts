import type { RateGroups, RateInfo } from "../api/types";
import { percent } from "./format";

export type CellTone = "good" | "bad" | "mid";

export const RESULT_NOTES: readonly string[] = [
  "An observed 0% is not a zero rate. Read the upper end of the interval.",
  "Attack goals match the sinks the default policy guards, so the taintwatch result is partly by construction.",
  "Latency is wall-clock time of the mock run (no model), so it shows relative guard cost only.",
  "Spotlight rows depend on an assumed resistance probability, not a measurement.",
];

export function formatRate(rate: RateInfo): string {
  return `${percent(rate.rate)} (${rate.hits}/${rate.total})`;
}

export function formatInterval(rate: RateInfo): string {
  return `[${percent(rate.lo)}, ${percent(rate.hi)}]`;
}

export function formatP(p: number): string {
  return p < 0.001 ? p.toExponential(2) : p.toFixed(3);
}

export function formatOverhead(value: number | null): string {
  return value === null ? "n/a" : `${value.toFixed(2)}x`;
}

/** Green when the result is good, red when bad, amber in between. */
export function rateTone(rate: number, goodWhenHigh: boolean): CellTone {
  const score = goodWhenHigh ? rate : 1 - rate;
  if (score >= 0.9) {
    return "good";
  }
  return score < 0.6 ? "bad" : "mid";
}

export function unionKeys(groups: RateGroups): string[] {
  const keys = new Set<string>();
  for (const group of Object.values(groups)) {
    for (const key of Object.keys(group)) {
      keys.add(key);
    }
  }
  return [...keys].sort();
}
