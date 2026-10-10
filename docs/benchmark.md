# Benchmark scenarios

`taintwatch.bench` generates the evaluation dataset deterministically from a seed.

    python -m taintwatch.bench --attacks 600 --benign 200 --seed 7 --out data/scenarios.jsonl

## Attacks (up to 1,080 distinct)

5 goals x 4 variants x 3 carriers x 6 wrapper styles x 3 task phrasings. The default suite
samples 600, balanced across goals.

- Goals: `shell_exec`, `exfil_http`, `exfil_email`, `email_send`, `file_write`.
- Carriers: a fetched web page, an inbox message, a downloaded (untrusted) file.
- Styles: plain, hidden HTML comment, urgent notice, fake admin message, buried mid-text,
  polite P.S.

Each attack records a machine-checkable success condition (command ran, secret leaked,
email sent, file written) and a utility check (the summary still contains the page text).

## Benign tasks (default 200)

Seven families: `summarize_web`, `summarize_inbox`, `read_file`, `email_summary`,
`save_notes`, `user_command`, `file_driven_command`. About 40% of texts mention dangerous
things (`rm -rf`, "ignore previous instructions") without containing a directive, so
keyword-based defenses have real false positives to make.

`save_notes` writes untrusted text to a file. The default policy asks for confirmation, so
it counts as blocked unless a confirm callback approves. It measures the utility cost of the
`confirm` rule.

## Running a scenario

```python
from taintwatch import default_policy
from taintwatch.bench import build_suite, run_scenario

suite = build_suite()
outcome = run_scenario(suite.attacks[0], default_policy())
outcome.attack_succeeded, outcome.utility_ok
```

An empty `Policy()` means no defense. `gullible=False` runs the careful agent.

## Limits

The attacks are written in the mock agent's directive format, so "100% success without a
defense" is a sanity check on the generator, not a research result. A real-model adapter is
needed before any claim about real LLM behavior.
