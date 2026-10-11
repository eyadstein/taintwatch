import { describe, expect, it } from "vitest";
import type { RateGroups, RateInfo } from "../api/types";
import {
  formatInterval,
  formatOverhead,
  formatP,
  formatRate,
  rateTone,
  unionKeys,
} from "./results";

const rate = (hits: number, total: number): RateInfo => ({
  hits,
  total,
  rate: hits / total,
  lo: 0.1,
  hi: 0.3,
});

describe("formatters", () => {
  it("formats rates and intervals", () => {
    expect(formatRate(rate(172, 200))).toBe("86.0% (172/200)");
    expect(formatInterval(rate(1, 2))).toBe("[10.0%, 30.0%]");
  });

  it("formats p-values", () => {
    expect(formatP(4.82e-181)).toBe("4.82e-181");
    expect(formatP(0.25)).toBe("0.250");
    expect(formatP(1)).toBe("1.000");
  });

  it("formats overhead", () => {
    expect(formatOverhead(1.274)).toBe("1.27x");
    expect(formatOverhead(null)).toBe("n/a");
  });
});

describe("rateTone", () => {
  it("is good when low rates are good", () => {
    expect(rateTone(0, false)).toBe("good");
    expect(rateTone(0.27, false)).toBe("mid");
    expect(rateTone(1, false)).toBe("bad");
  });

  it("is good when high rates are good", () => {
    expect(rateTone(1, true)).toBe("good");
    expect(rateTone(0.86, true)).toBe("mid");
    expect(rateTone(0, true)).toBe("bad");
  });
});

describe("unionKeys", () => {
  it("collects sorted keys across defenses", () => {
    const groups: RateGroups = {
      a: { y: rate(1, 2), x: rate(1, 2) },
      b: { z: rate(1, 2) },
    };
    expect(unionKeys(groups)).toEqual(["x", "y", "z"]);
    expect(unionKeys({})).toEqual([]);
  });
});
