# Taintwatch

Runtime information-flow control for LLM agents. Every piece of data carries an
integrity and confidentiality label plus a provenance trail. Tool calls are
checked against a declarative policy, so untrusted text (a web page, an inbound
email) cannot silently steer shell commands or leak secrets.

Status: early research prototype.

## Policy language

Policies can be written in a small purpose-built language with a static validator.
See `docs/policy-language.md` and `policies/default.twp`.

## Span-level tracking

`taintwatch.spans.TStr` labels character ranges instead of whole values.
See `docs/span-tracking.md`.

## Agent runtime

`taintwatch.agent` provides a tool registry, a simulated world and a runtime that routes
every tool call through the guard. See `docs/agent-runtime.md`.

## Benchmark

`taintwatch.bench` generates 600+ attack scenarios and 200 benign tasks from a seed.
See `docs/benchmark.md`. The generated dataset is in `data/scenarios.jsonl`.

## Baselines

`taintwatch.baselines` implements the defenses we compare against: keyword filter,
heuristic scorer, a spotlighting model and a coarse-taint ablation.
Try `python -m taintwatch.baselines`. See `docs/baselines.md`.

## Evaluation

`python -m taintwatch.evaluation` runs the benchmark under every defense and writes
`results/records.csv`, `results/summary.json` and `results/report.md`.
See `docs/evaluation.md`.

## Server

`python -m taintwatch.server` serves a REST API over the benchmark with a SQLite trace store.
Install with `pip install -e ".[dev,server]"`. See `docs/server.md`.
