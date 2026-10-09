from pathlib import Path

from taintwatch.dsl import Severity, lint

DEFAULT_FILE = Path(__file__).resolve().parents[1] / "policies" / "default.twp"
TOOLS = ["shell.run", "email.send", "http.get", "fs.write"]


def messages(source: str, tools: list[str] | None = None) -> list[str]:
    return [str(d) for d in lint(source, tools or [])]


def test_default_policy_is_clean() -> None:
    assert lint(DEFAULT_FILE.read_text(encoding="utf-8"), TOOLS) == []


def test_duplicate_names_are_errors() -> None:
    source = "rule a: block t when integrity < user\nrule a: block u when integrity < user"
    diagnostics = lint(source)
    assert any(d.severity is Severity.ERROR for d in diagnostics)


def test_vacuous_integrity_condition() -> None:
    found = messages("rule r: block t when integrity < untrusted")
    assert any("never be true" in m for m in found)


def test_vacuous_confidentiality_condition() -> None:
    found = messages("rule r: block t when confidentiality > secret")
    assert any("never be true" in m for m in found)


def test_narrower_rule_is_redundant() -> None:
    source = (
        "rule broad: block shell.* when integrity < user\n"
        "rule narrow: block shell.run when integrity < tool_output\n"
    )
    redundant = [d for d in lint(source) if "redundant" in d.message]
    assert [d.rule for d in redundant] == ["narrow"]


def test_identical_rules_flag_only_the_later_one() -> None:
    source = "rule one: block t when integrity < user\nrule two: block t when integrity < user"
    redundant = [d for d in lint(source) if "redundant" in d.message]
    assert [d.rule for d in redundant] == ["two"]


def test_confirm_is_redundant_next_to_block_but_not_the_reverse() -> None:
    source = (
        "rule soft: confirm t when integrity < user\n"
        "rule hard: block t when integrity < user\n"
    )
    redundant = [d for d in lint(source) if "redundant" in d.message]
    assert [d.rule for d in redundant] == ["soft"]


def test_independent_conditions_are_not_redundant() -> None:
    source = (
        "rule a: block t when integrity < user\n"
        "rule b: block t when confidentiality > internal\n"
    )
    assert not [d for d in lint(source) if "redundant" in d.message]


def test_unknown_tool_pattern_and_uncovered_tool() -> None:
    found = messages("rule r: block email.send when integrity < user", ["shell.run"])
    assert any("matches no known tool" in m for m in found)
    assert any("'shell.run' has no rule" in m for m in found)
