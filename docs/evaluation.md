# Evaluation

`taintwatch.evaluation` runs every benchmark scenario under every defense and writes
machine-readable results plus a Markdown report.

    python -m taintwatch.evaluation
    python -m taintwatch.evaluation --defenses none taintwatch scorer@1.5 scorer@3.5 --repeats 5
    python -m taintwatch.evaluation --confirm --out results-confirm

Outputs in `results/`:

- `records.csv`: one row per (defense, scenario) run, with outcomes, blocks, steps, latency
  and the scenario tags. `read_records` loads it back into `RunRecord` objects.
- `summary.json`: per-defense rates with 95% Wilson intervals, latency and paired tests.
- `report.md`: overall table, attack success by goal, carrier and style, benign utility by
  family, and paired comparisons against `taintwatch`.

## Statistics

- Rates carry 95% Wilson score intervals. They stay informative at 0 and 100%: 0 successes in
  600 attacks still leaves an upper bound of about 0.6%.
- The paired comparison is an exact McNemar test on the attacks that succeed against one
  defense but not the other, matched by scenario id.
- Latency is the median over `--repeats` runs. Outcomes are deterministic for a given seed.

## Limits

- Latency is mock-run wall-clock time (no model). It shows relative guard cost only.
- "Benign policy blocks" counts guard blocks. Filter-style baselines show up as lost utility.
- Attack goals match the guarded sinks, so the taintwatch result is partly by construction.
- Spotlight rows depend on an assumed resistance probability.
