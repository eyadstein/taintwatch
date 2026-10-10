# Baseline defenses

A `Defense` bundles a policy for the guard with an optional wrapper around the agent.
`run_defended(scenario, defense)` runs any scenario under any defense.

| Spec | Meaning |
|---|---|
| `none` | No protection. |
| `taintwatch` | Span-level IFC with the default policy. |
| `taintwatch-coarse` | Ablation: the same policy, but each call carries the taint of the whole context. |
| `keyword` | Removes tool output containing a suspicious phrase (`taintwatch.baselines.keyword`). |
| `scorer@T` | Removes tool output whose weighted heuristic score reaches `T` (default 2.5). |
| `spotlight@R` | Untrusted tool output is treated as data with probability `R` (default 0.9). |

    python -m taintwatch.baselines
    python -m taintwatch.baselines --defenses none taintwatch scorer@1.5 scorer@3.5
    python -m taintwatch.baselines --confirm   # auto-approve confirm verdicts

## Limits

- The keyword list and scorer weights are hand-written baselines. They do not use the mock
  agent's directive syntax, but a stronger or weaker list would change the numbers. Compare
  against a published detector before making claims.
- The scorer is not trained. "Classifier-style" describes its interface only.
- Spotlighting cannot be measured with a scripted agent. `R` is an assumption, so report a
  sweep over `R`, not a single value.
- The default policy guards the same sinks the attacks target. Attacks outside those sinks
  are needed for a fair evaluation.
- Utility checks for `email_summary` and `save_notes` only verify that the action happened.
- With `--confirm`, `file_write` attacks succeed under `taintwatch`: an approval prompt that
  always says yes is not a defense.
