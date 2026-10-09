from pathlib import Path

import pytest

from taintwatch.dsl import DslError, compile_policy, load_policy
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.policy import Action, default_policy
from taintwatch.tainted import Labeled

DEFAULT_FILE = Path(__file__).resolve().parents[1] / "policies" / "default.twp"


def test_strict_comparisons() -> None:
    policy = compile_policy(
        "rule r: block t when integrity < user or confidentiality > internal"
    )
    (rule,) = policy.rules
    assert rule.min_integrity is Integrity.USER
    assert rule.max_confidentiality is Confidentiality.INTERNAL
    assert rule.action is Action.BLOCK


def test_inclusive_comparisons_shift_the_threshold() -> None:
    policy = compile_policy(
        "rule r: confirm t when integrity <= tool_output or confidentiality >= internal"
    )
    (rule,) = policy.rules
    assert rule.min_integrity is Integrity.USER
    assert rule.max_confidentiality is Confidentiality.PUBLIC
    assert rule.action is Action.CONFIRM


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("rule r: block t when integrity > user", "integrity conditions"),
        ("rule r: block t when confidentiality < secret", "confidentiality conditions"),
        ("rule r: block t when integrity < banana", "unknown integrity level"),
        ("rule r: block t when integrity <= system", "always true"),
        ("rule r: block t when confidentiality >= public", "always true"),
        ("rule r: block t when integrity < user or integrity < system", "at most one"),
        (
            "rule r: block t when integrity < user\nrule r: block u when integrity < user",
            "duplicate rule name",
        ),
    ],
)
def test_semantic_errors(source: str, message: str) -> None:
    with pytest.raises(DslError, match=message):
        compile_policy(source)


def test_compiled_policy_enforces_rules() -> None:
    policy = compile_policy("rule r: block shell.* when integrity < user")
    tainted = Labeled("x", "n1", Label(Integrity.UNTRUSTED))
    trusted = Labeled("x", "n2", Label(Integrity.USER))
    assert policy.evaluate("shell.run", {"cmd": tainted}).action is Action.BLOCK
    assert policy.evaluate("shell.run", {"cmd": trusted}).allowed


def test_default_file_matches_toml_default() -> None:
    assert load_policy(DEFAULT_FILE).rules == default_policy().rules
