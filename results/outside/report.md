# Taintwatch: attacks outside the default policy

200 attacks and 200 benign tasks per defense. Intervals are 95% Wilson score intervals.

## Overall

| defense | attack success (95% CI) | benign utility | utility under attack | benign policy blocks | median ms | p95 ms | overhead |
|---|---|---|---|---|---|---|---|
| none | 100.0% [98.1%, 100.0%] | 100.0% | 100.0% | 0.0% | 0.353 | 0.648 | 1.00x |
| taintwatch | 100.0% [98.1%, 100.0%] | 86.0% | 100.0% | 14.0% | 0.366 | 0.625 | 1.04x |
| taintwatch-strict | 50.0% [43.1%, 56.9%] | 86.0% | 100.0% | 14.0% | 0.348 | 0.563 | 0.98x |
| keyword | 47.0% [40.2%, 53.9%] | 83.0% | 47.0% | 0.0% | 0.324 | 0.609 | 0.92x |
| scorer@2.5 | 47.0% [40.2%, 53.9%] | 91.0% | 47.0% | 0.0% | 0.402 | 0.649 | 1.14x |

## Attack success by goal

| defense | answer_poison | exfil_get | exfil_internal | exfil_mislabeled |
|---|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch-strict | 100.0% | 0.0% | 0.0% | 100.0% |
| keyword | 42.0% | 48.0% | 48.0% | 50.0% |
| scorer@2.5 | 42.0% | 48.0% | 48.0% | 50.0% |

## Attack success by carrier

| defense | email | file | web |
|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% |
| taintwatch | 100.0% | 100.0% | 100.0% |
| taintwatch-strict | 55.1% | 45.0% | 49.3% |
| keyword | 55.1% | 53.3% | 33.8% |
| scorer@2.5 | 55.1% | 53.3% | 33.8% |

## Attack success by style

| defense | authority | buried | hidden_comment | plain | polite | urgent |
|---|---|---|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch-strict | 55.9% | 55.9% | 53.3% | 36.7% | 51.5% | 46.2% |
| keyword | 0.0% | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| scorer@2.5 | 0.0% | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |

## Benign utility by family

| defense | benign/email_summary | benign/file_driven_command | benign/read_file | benign/save_notes | benign/summarize_inbox | benign/summarize_web | benign/user_command |
|---|---|---|---|---|---|---|---|
| none | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| taintwatch | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |
| taintwatch-strict | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |
| keyword | 100.0% | 100.0% | 58.6% | 100.0% | 55.2% | 69.0% | 100.0% |
| scorer@2.5 | 100.0% | 100.0% | 82.8% | 100.0% | 72.4% | 82.8% | 100.0% |

## Paired comparison against taintwatch

| defense | attacks that succeed only against it | attacks that succeed only against taintwatch | exact McNemar p |
|---|---|---|---|
| none | 0 | 0 | 1.000 |
| taintwatch-strict | 0 | 100 | 1.58e-30 |
| keyword | 0 | 106 | 2.47e-32 |
| scorer@2.5 | 0 | 106 | 2.47e-32 |

## Notes

- These attacks target channels the default policy leaves open. High success rates here are expected and show where it fails; they are not a regression.
- exfil_get leaks through a web.fetch URL (the policy linter reports web.fetch as having no rule). exfil_internal leaks data labeled internal, which the default threshold allows. exfil_mislabeled leaks data carrying a wrong public label. answer_poison changes what the user is told without any tool call.
- taintwatch-strict tightens confidentiality thresholds and covers web.*. It has no rule about where data is sent, so it cannot stop mislabeled data, and nothing in this policy language constrains the final answer.
- Benign utility is measured on the main benign tasks.
- An observed 0% is not a zero rate. Read the upper end of the interval.
