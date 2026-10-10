import { describe, expect, it } from "vitest";
import type { Segment } from "../api/types";
import {
  describeOutcome,
  formatArgs,
  integrityCounts,
  percent,
  truncate,
  untrustedShare,
} from "./format";

const seg = (text: string, integrity: Segment["integrity"]): Segment => ({
  text,
  integrity,
  confidentiality: "PUBLIC",
  sources: [],
});

describe("integrity helpers", () => {
  it("counts characters per level", () => {
    const counts = integrityCounts([seg("abcd", "USER"), seg("xy", "UNTRUSTED"), seg("z", "USER")]);
    expect(counts).toEqual({ UNTRUSTED: 2, TOOL_OUTPUT: 0, USER: 5, SYSTEM: 0 });
  });

  it("computes the untrusted share", () => {
    expect(untrustedShare([seg("abcd", "USER"), seg("xy", "UNTRUSTED")])).toBeCloseTo(1 / 3);
    expect(untrustedShare([])).toBe(0);
  });
});

describe("text helpers", () => {
  it("truncates long text and keeps short text", () => {
    expect(truncate("abcdefghij", 8)).toBe("abcde...");
    expect(truncate("abc", 8)).toBe("abc");
    expect(() => truncate("abc", 3)).toThrow(RangeError);
  });

  it("formats arguments", () => {
    const args = [
      { name: "to", value: "a@b.c" },
      { name: "body", value: "0123456789" },
    ];
    expect(formatArgs(args, 8)).toBe("to=a@b.c, body=01234...");
    expect(formatArgs([])).toBe("");
  });

  it("formats percentages", () => {
    expect(percent(0.1234)).toBe("12.3%");
  });
});

describe("describeOutcome", () => {
  it("labels attacks", () => {
    expect(describeOutcome({ is_attack: true, attack_succeeded: true, utility_ok: true })).toEqual({
      label: "attack succeeded",
      tone: "bad",
    });
    expect(describeOutcome({ is_attack: true, attack_succeeded: false, utility_ok: true })).toEqual({
      label: "attack stopped",
      tone: "good",
    });
  });

  it("labels benign tasks", () => {
    expect(describeOutcome({ is_attack: false, attack_succeeded: false, utility_ok: true }).label).toBe(
      "task completed",
    );
    expect(describeOutcome({ is_attack: false, attack_succeeded: false, utility_ok: false })).toEqual({
      label: "task failed",
      tone: "bad",
    });
  });
});
