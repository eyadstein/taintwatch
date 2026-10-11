import { describe, expect, it } from "vitest";
import {
  compareRows,
  describeCheck,
  familyLabel,
  formatPlanArgs,
  splitDirectives,
  totalPages,
} from "./scenario";

describe("splitDirectives", () => {
  it("separates directives from surrounding text", () => {
    const parts = splitDirectives('a <<call x.y k="v">> b');
    expect(parts).toEqual([
      { text: "a ", directive: false },
      { text: '<<call x.y k="v">>', directive: true },
      { text: " b", directive: false },
    ]);
  });

  it("handles several directives, none, and empty text", () => {
    expect(splitDirectives("<<call a.b>><<call c.d>>").map((p) => p.directive)).toEqual([true, true]);
    expect(splitDirectives("just news")).toEqual([{ text: "just news", directive: false }]);
    expect(splitDirectives("")).toEqual([]);
  });

  it("keeps the original text when joined", () => {
    const text = "x <!-- <<call a.b k=\"1\">> --> y";
    expect(splitDirectives(text).map((p) => p.text).join("")).toBe(text);
  });
});

describe("describeCheck", () => {
  it("describes every effect", () => {
    expect(describeCheck({ effect: "command_ran", value: "ls" })).toBe('a command containing "ls" runs');
    expect(describeCheck({ effect: "secret_leaked", value: "sk-1" })).toBe(
      'the secret "sk-1" leaves in an email or request',
    );
    expect(describeCheck({ effect: "email_to", value: "a@b.c" })).toBe("an email is sent to a@b.c");
    expect(describeCheck({ effect: "file_written", value: "/x" })).toBe("the file /x is written");
    expect(describeCheck({ effect: "answer_has", value: "hi" })).toBe(
      'the final answer contains "hi"',
    );
    expect(describeCheck({ effect: "other", value: "v" })).toBe("other: v");
  });
});

describe("small helpers", () => {
  it("labels families", () => {
    expect(familyLabel("attack/shell_exec")).toBe("shell_exec");
    expect(familyLabel("plain")).toBe("plain");
  });

  it("counts pages", () => {
    expect(totalPages(0, 25)).toBe(1);
    expect(totalPages(25, 25)).toBe(1);
    expect(totalPages(26, 25)).toBe(2);
    expect(totalPages(800, 25)).toBe(32);
    expect(() => totalPages(10, 0)).toThrow(RangeError);
  });

  it("formats plan arguments", () => {
    expect(formatPlanArgs({ a: "1", b: "2" })).toBe("a=1, b=2");
    expect(formatPlanArgs({})).toBe("");
    expect(formatPlanArgs({ a: "0123456789" }, 8)).toBe("a=01234...");
  });
});

describe("compareRows", () => {
  const base = { is_attack: true, utility_ok: true, steps: 3 };

  it("marks the rows that differ", () => {
    const rows = compareRows(
      { ...base, attack_succeeded: true, blocked: 0, calls: 2 },
      { ...base, attack_succeeded: false, blocked: 1, calls: 1 },
    );
    expect(rows.map((r) => [r.label, r.differs])).toEqual([
      ["Outcome", true],
      ["Blocked calls", true],
      ["Tool calls", true],
      ["Steps", false],
    ]);
    expect(rows[0]).toMatchObject({ a: "attack succeeded", b: "attack stopped" });
  });
});
