"""A stricter policy: public-only egress and a rule for web fetches.

It deliberately has no rule about where data may be sent, so it cannot stop data that
carries the wrong label. The linter shows which tools it covers.
"""

from __future__ import annotations

from taintwatch.dsl import compile_policy
from taintwatch.policy import Policy

STRICT_POLICY_TEXT = """\
# Taintwatch strict policy. Equivalent to policies/strict.twp.

rule untrusted-input-to-shell: block shell.* when integrity < user
    because "Shell commands must not be influenced by untrusted content."

rule untrusted-email-recipient: block email.send(to) when integrity < user
    because "Only the user may choose who receives email."

rule nonpublic-leaves-via-email: block email.send when confidentiality > public

rule nonpublic-leaves-via-http: block http.* when confidentiality > public

rule nonpublic-leaves-via-web: block web.* when confidentiality > public
    because "A fetched URL can carry data out in its query string."

rule untrusted-file-write: confirm fs.write(content) when integrity < tool_output
"""


def strict_policy() -> Policy:
    return compile_policy(STRICT_POLICY_TEXT)
