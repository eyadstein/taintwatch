# Taintwatch benchmark results

600 attacks and 200 benign tasks per defense. Intervals are 95% Wilson score intervals.

## Overall

| defense | attack success (95% CI) | benign utility | utility under attack | benign policy blocks | median ms | p95 ms | overhead |
|---|---|---|---|---|---|---|---|
| none | 100.0% [99.4%, 100.0%] | 100.0% | 100.0% | 0.0% | 0.215 | 0.331 | 1.00x |
| taintwatch | 0.0% [0.0%, 0.6%] | 86.0% | 100.0% | 14.0% | 0.272 | 0.430 | 1.27x |
| taintwatch-coarse | 0.0% [0.0%, 0.6%] | 71.5% | 100.0% | 28.5% | 0.309 | 0.532 | 1.44x |
| keyword | 27.0% [23.6%, 30.7%] | 83.0% | 27.0% | 0.0% | 0.197 | 0.396 | 0.92x |
| scorer@2.5 | 31.0% [27.4%, 34.8%] | 91.0% | 31.0% | 0.0% | 0.426 | 0.853 | 1.99x |
| spotlight@0.9 | 8.7% [6.7%, 11.2%] | 100.0% | 100.0% | 0.0% | 0.192 | 0.345 | 0.90x |

## Attack success by goal

| defense | email_send | exfil_email | exfil_http | file_write | shell_exec |
|---|---|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| taintwatch-coarse | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| keyword | 30.8% | 45.8% | 45.0% | 13.3% | 0.0% |
| scorer@2.5 | 38.3% | 45.8% | 45.0% | 25.8% | 0.0% |
| spotlight@0.9 | 7.5% | 9.2% | 12.5% | 7.5% | 6.7% |

## Attack success by carrier

| defense | email | file | web |
|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% |
| taintwatch | 0.0% | 0.0% | 0.0% |
| taintwatch-coarse | 0.0% | 0.0% | 0.0% |
| keyword | 28.6% | 26.2% | 26.2% |
| scorer@2.5 | 31.7% | 31.4% | 30.0% |
| spotlight@0.9 | 10.6% | 7.9% | 7.6% |

## Attack success by style

| defense | authority | buried | hidden_comment | plain | polite | urgent |
|---|---|---|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| taintwatch-coarse | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| keyword | 0.0% | 56.4% | 60.9% | 56.6% | 0.0% | 0.0% |
| scorer@2.5 | 0.0% | 69.1% | 64.4% | 65.7% | 0.0% | 0.0% |
| spotlight@0.9 | 5.3% | 6.4% | 6.9% | 11.1% | 10.2% | 11.1% |

## Benign utility by family

| defense | benign/email_summary | benign/file_driven_command | benign/read_file | benign/save_notes | benign/summarize_inbox | benign/summarize_web | benign/user_command |
|---|---|---|---|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |
| taintwatch-coarse | 0.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |
| keyword | 100.0% | 100.0% | 58.6% | 100.0% | 55.2% | 69.0% | 100.0% |
| scorer@2.5 | 100.0% | 100.0% | 82.8% | 100.0% | 72.4% | 82.8% | 100.0% |
| spotlight@0.9 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |

## Paired comparison against taintwatch

| defense | attacks that succeed only against it | attacks that succeed only against taintwatch | exact McNemar p |
|---|---|---|---|
| none | 600 | 0 | 4.82e-181 |
| taintwatch-coarse | 0 | 0 | 1.000 |
| keyword | 162 | 0 | 3.42e-49 |
| scorer@2.5 | 186 | 0 | 2.04e-56 |
| spotlight@0.9 | 52 | 0 | 4.44e-16 |

## Notes

- Latency is wall-clock time of the mock run (agent, guard and tools, no model). It shows relative guard cost only; real model latency would dominate.
- An observed 0% is not a zero rate. Read the upper end of the interval.
- Benign policy blocks counts guard blocks only. Filter-style defenses act before the runtime and show up as lost utility instead.
- Spotlight rows depend on an assumed resistance probability, not a measurement.
- Attack goals match the sinks the default policy guards, so the taintwatch result is partly by construction.
