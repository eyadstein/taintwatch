# Policy language

A policy is a list of rules. Comments start with `#`; whitespace and newlines are free-form.

    rule NAME: ACTION TOOL[(ARG)] when CONDITION [or CONDITION] [because "text"]

- `ACTION` is `block` or `confirm`. The strictest violated rule wins.
- `TOOL` and `ARG` are glob patterns (`shell.*`, `email.send(to)`). `ARG` defaults to `*`.
- `CONDITION` is `integrity < LEVEL`, `integrity <= LEVEL`, `confidentiality > LEVEL`
  or `confidentiality >= LEVEL`. A rule fires when any of its conditions holds.
- Integrity levels: `untrusted < tool_output < user < system`.
- Confidentiality levels: `public < internal < secret`.
- At most one integrity and one confidentiality condition per rule.

## Static checks

Run `python -m taintwatch.dsl policies/default.twp shell.run email.send http.get fs.write`.
The extra arguments are the tools your agent can call. The linter reports duplicate rule names
(error), conditions that can never be true, redundant rules, tool patterns that match no known
tool, and known tools with no rule (warnings).
