import type { EventArg, EventKind, Integrity, RunSummary, Segment } from "../api/types";

export const INTEGRITY_ORDER: readonly Integrity[] = ["UNTRUSTED", "TOOL_OUTPUT", "USER", "SYSTEM"];

export const INTEGRITY_LABEL: Record<Integrity, string> = {
  UNTRUSTED: "untrusted",
  TOOL_OUTPUT: "tool output",
  USER: "user",
  SYSTEM: "system",
};

export const EVENT_LABEL: Record<EventKind, string> = {
  call: "ran",
  blocked: "blocked",
  error: "error",
  finish: "finished",
};

export type Tone = "good" | "bad" | "neutral";

export function integrityCounts(segments: readonly Segment[]): Record<Integrity, number> {
  const counts: Record<Integrity, number> = { UNTRUSTED: 0, TOOL_OUTPUT: 0, USER: 0, SYSTEM: 0 };
  for (const segment of segments) {
    counts[segment.integrity] += segment.text.length;
  }
  return counts;
}

export function untrustedShare(segments: readonly Segment[]): number {
  const counts = integrityCounts(segments);
  const total = counts.UNTRUSTED + counts.TOOL_OUTPUT + counts.USER + counts.SYSTEM;
  return total === 0 ? 0 : counts.UNTRUSTED / total;
}

export function truncate(text: string, max: number): string {
  if (max < 4) {
    throw new RangeError("max must be at least 4");
  }
  return text.length <= max ? text : `${text.slice(0, max - 3)}...`;
}

export function formatArgs(args: readonly EventArg[], max = 60): string {
  return args.map((arg) => `${arg.name}=${truncate(arg.value, max)}`).join(", ");
}

export function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

export function describeOutcome(
  run: Pick<RunSummary, "is_attack" | "attack_succeeded" | "utility_ok">,
): { label: string; tone: Tone } {
  if (run.is_attack) {
    return run.attack_succeeded
      ? { label: "attack succeeded", tone: "bad" }
      : { label: "attack stopped", tone: "good" };
  }
  return run.utility_ok
    ? { label: "task completed", tone: "good" }
    : { label: "task failed", tone: "bad" };
}
