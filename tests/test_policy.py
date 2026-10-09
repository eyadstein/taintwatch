import pytest

from taintwatch.errors import PolicyError
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.policy import Action, Policy, default_policy
from taintwatch.tainted import Labeled


def make(
    value: str, integrity: Integrity, conf: Confidentiality = Confidentiality.PUBLIC
) -> Labeled[str]:
    return Labeled(value, "n1", Label(integrity, conf))


def test_default_policy_blocks_untrusted_shell_input() -> None:
    args = {"cmd": make("rm -rf /", Integrity.UNTRUSTED)}
    verdict = default_policy().evaluate("shell.run", args)
    assert verdict.action is Action.BLOCK
    assert verdict.violations[0].rule.name == "untrusted-input-to-shell"


def test_default_policy_allows_user_shell_input() -> None:
    verdict = default_policy().evaluate("shell.run", {"cmd": make("ls", Integrity.USER)})
    assert verdict.allowed


def test_secret_in_email_body_is_blocked() -> None:
    args = {
        "to": make("a@b.com", Integrity.USER),
        "body": make("key", Integrity.USER, Confidentiality.SECRET),
    }
    assert default_policy().evaluate("email.send", args).action is Action.BLOCK


def test_untrusted_file_content_requires_confirmation() -> None:
    args = {"path": make("a.txt", Integrity.USER), "content": make("x", Integrity.UNTRUSTED)}
    assert default_policy().evaluate("fs.write", args).action is Action.CONFIRM


def test_strictest_action_wins() -> None:
    policy = Policy.from_toml(
        """
        [[rule]]
        name = "soft"
        tool = "t"
        min_integrity = "user"
        action = "confirm"

        [[rule]]
        name = "hard"
        tool = "t"
        min_integrity = "user"
        action = "block"
        """
    )
    assert policy.evaluate("t", {"a": make("x", Integrity.UNTRUSTED)}).action is Action.BLOCK


def test_unmatched_tool_is_allowed() -> None:
    args = {"q": make("x", Integrity.UNTRUSTED)}
    assert default_policy().evaluate("calendar.read", args).allowed


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy.from_toml('[[rule]]\nname = "x"\ntool = "t"\nbogus = 1')


def test_missing_required_field_is_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy.from_toml('[[rule]]\nname = "x"')


def test_invalid_level_is_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy.from_toml('[[rule]]\nname = "x"\ntool = "t"\nmin_integrity = "super"')


def test_invalid_toml_is_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy.from_toml("[[rule")
