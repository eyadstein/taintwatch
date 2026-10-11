import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RateInfo, ResultsData } from "../api/types";
import { RateBars } from "./RateBars";
import { ResultsDashboard } from "./ResultsDashboard";

const rate = (hits: number, total: number, lo: number, hi: number): RateInfo => ({
  hits,
  total,
  rate: hits / total,
  lo,
  hi,
});

const data: ResultsData = {
  pivot: "taintwatch",
  defenses: [
    {
      defense: "none",
      attack_success: rate(600, 600, 0.994, 1),
      utility_under_attack: rate(600, 600, 0.994, 1),
      benign_utility: rate(200, 200, 0.981, 1),
      benign_blocked: rate(0, 200, 0, 0.019),
      latency_median_ms: 0.2,
      latency_p95_ms: 0.3,
      overhead: 1,
    },
    {
      defense: "taintwatch",
      attack_success: rate(0, 600, 0, 0.006),
      utility_under_attack: rate(600, 600, 0.994, 1),
      benign_utility: rate(172, 200, 0.805, 0.903),
      benign_blocked: rate(28, 200, 0.099, 0.194),
      latency_median_ms: 0.27,
      latency_p95_ms: 0.43,
      overhead: 1.27,
    },
  ],
  attack_breakdown: {
    goal: {
      none: { shell_exec: rate(120, 120, 0.97, 1) },
      taintwatch: { shell_exec: rate(0, 120, 0, 0.03) },
    },
  },
  benign_breakdown: {
    none: { "benign/save_notes": rate(2, 2, 0.34, 1) },
    taintwatch: { "benign/save_notes": rate(0, 2, 0, 0.66) },
  },
  paired: [
    {
      defense: "none",
      pivot: "taintwatch",
      only_defense_succeeds: 600,
      only_pivot_succeeds: 0,
      mcnemar_p: 4.82e-181,
    },
  ],
};

describe("RateBars", () => {
  const rows = [
    { label: "none", rate: rate(600, 600, 0.994, 1) },
    { label: "taintwatch", rate: rate(0, 600, 0, 0.006) },
  ];
  const html = renderToStaticMarkup(<RateBars title="Attack success" rows={rows} tone="bad" />);

  it("is an accessible chart with a label and a value for every row", () => {
    expect(html).toContain('role="img"');
    expect(html).toContain('aria-label="Attack success"');
    expect(html).toContain(">none<");
    expect(html).toContain("100.0% (600/600)");
    expect(html).toContain("0.0% (0/600)");
  });

  it("draws the bars in the requested tone", () => {
    expect(html).toContain("chart-bad");
    expect(html).not.toContain("chart-good");
  });
});

describe("ResultsDashboard", () => {
  const html = renderToStaticMarkup(<ResultsDashboard data={data} />);

  it("summarizes the run size and the overall table", () => {
    expect(html).toContain("600 attacks and 200 benign tasks per defense");
    expect(html).toContain("0.0% [0.0%, 0.6%]");
    expect(html).toContain("1.27x");
    expect(html).toContain("86.0%");
  });

  it("shows both charts and the breakdown tables", () => {
    expect(html).toContain("Attack success (lower is better)");
    expect(html).toContain("Benign utility (higher is better)");
    expect(html).toContain("Attack success by goal");
    expect(html).toContain("Benign utility by family");
    expect(html).toContain("shell_exec");
    expect(html).toContain(">save_notes<");
  });

  it("colors cells by how good the result is", () => {
    expect(html).toContain("cell-bad");
    expect(html).toContain("cell-good");
  });

  it("shows the paired test and the notes", () => {
    expect(html).toContain("Paired comparison against taintwatch");
    expect(html).toContain("4.82e-181");
    expect(html).toContain("not a zero rate");
    expect(html).toContain("partly by construction");
  });
});
