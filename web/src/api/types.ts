export type Integrity = "UNTRUSTED" | "TOOL_OUTPUT" | "USER" | "SYSTEM";
export type Confidentiality = "PUBLIC" | "INTERNAL" | "SECRET";
export type EventKind = "call" | "blocked" | "error" | "finish";

export interface Segment {
  text: string;
  integrity: Integrity;
  confidentiality: Confidentiality;
  sources: string[];
}

export interface EventArg {
  name: string;
  value: string;
}

export interface TraceEvent {
  step: number;
  kind: EventKind;
  tool: string;
  args: EventArg[];
  detail: string;
}

export interface RunSummary {
  id: number;
  created_at: string;
  scenario_id: string;
  family: string;
  defense: string;
  task: string;
  seed: number;
  is_attack: boolean;
  attack_succeeded: boolean;
  utility_ok: boolean;
  blocked: number;
  calls: number;
  steps: number;
  truncated: boolean;
}

export interface RunDetail extends RunSummary {
  answer: string;
  context: Segment[];
  events: TraceEvent[];
}

export interface Page<T> {
  total: number;
  items: T[];
}

export interface ScenarioSummary {
  id: string;
  family: string;
  task: string;
  is_attack: boolean;
  meta: Record<string, string>;
}

export interface DefenseInfo {
  spec: string;
  name: string;
  description: string;
}

export interface HealthInfo {
  status: string;
  scenarios: number;
  runs: number;
}

export interface RunRequest {
  scenario_id: string;
  defense: string;
  seed?: number;
  confirm?: boolean;
}
