import type { CheckInfo, RunSummary } from "../api/types";
import { describeOutcome, truncate } from "./format";

export interface TextPart {
  text: string;
  directive: boolean;
}

const DIRECTIVE = /<<call\s[\s\S]*?>>/g;

/** Split text into plain parts and injected `<<call ...>>` directives, in order. */
export function splitDirectives(text: string): TextPart[] {
  const parts: TextPart[] = [];
  let last = 0;
  for (const match of text.matchAll(DIRECTIVE)) {
    const start = match.index ?? 0;
    if (start > last) {
      parts.push({ text: text.slice(last, start), directive: false });
    }
    parts.push({ text: match[0], directive: true });
    last = start + match[0].length;
  }
  if (last < text.length) {
    parts.push({ text: text.slice(last), directive: false });
  }
  return parts;
}

export function describeCheck(check: CheckInfo): string {
  switch (check.effect) {
    case "command_ran":
      return `a command containing "${check.value}" runs`;
    case "secret_leaked":
      return `the secret "${check.value}" leaves in an email or request`;
    case "email_to":
      return `an email is sent to ${check.value}`;
    case "file_written":
      return `the file ${check.value} is written`;
    case "answer_has":
      return `the final answer contains "${check.value}"`;
    default:
      return `${check.effect}: ${check.value}`;
  }
}

export function familyLabel(family: string): string {
  return family.split("/").pop() ?? family;
}

export function totalPages(total: number, size: number): number {
  if (size < 1) {
    throw new RangeError("size must be at least 1");
  }
  return Math.max(1, Math.ceil(total / size));
}

export function formatPlanArgs(args: Record<string, string>, max = 60): string {
  return Object.entries(args)
    .map(([name, value]) => `${name}=${truncate(value, max)}`)
    .join(", ");
}

export interface CompareRow {
  label: string;
  a: string;
  b: string;
  differs: boolean;
}

type Comparable = Pick<
  RunSummary,
  "is_attack" | "attack_succeeded" | "utility_ok" | "blocked" | "calls" | "steps"
>;

export function compareRows(a: Comparable, b: Comparable): CompareRow[] {
  const rows: [string, string, string][] = [
    ["Outcome", describeOutcome(a).label, describeOutcome(b).label],
    ["Blocked calls", String(a.blocked), String(b.blocked)],
    ["Tool calls", String(a.calls), String(b.calls)],
    ["Steps", String(a.steps), String(b.steps)],
  ];
  return rows.map(([label, x, y]) => ({ label, a: x, b: y, differs: x !== y }));
}
