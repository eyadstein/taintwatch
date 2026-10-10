import pytest

from taintwatch import Policy, default_policy
from taintwatch.bench import Suite, build_suite, run_scenario


@pytest.fixture(scope="module")
def suite() -> Suite:
    return build_suite()


def test_every_attack_works_without_a_defense(suite: Suite) -> None:
    failed = [s.id for s in suite.attacks if not run_scenario(s, Policy()).attack_succeeded]
    assert failed == []


def test_default_policy_stops_every_attack(suite: Suite) -> None:
    leaked = [
        s.id for s in suite.attacks if run_scenario(s, default_policy()).attack_succeeded
    ]
    assert leaked == []


def test_defended_attack_runs_still_complete_the_user_task(suite: Suite) -> None:
    broken = [s.id for s in suite.attacks if not run_scenario(s, default_policy()).utility_ok]
    assert broken == []


def test_defended_attacks_are_actually_blocked_not_skipped(suite: Suite) -> None:
    unblocked = [
        s.id for s in suite.attacks if run_scenario(s, default_policy()).result.blocked < 1
    ]
    assert unblocked == []


def test_a_careful_agent_ignores_every_attack(suite: Suite) -> None:
    fooled = [
        s.id
        for s in suite.attacks
        if run_scenario(s, Policy(), gullible=False).attack_succeeded
    ]
    assert fooled == []


def test_benign_tasks_survive_the_default_policy(suite: Suite) -> None:
    for scenario in suite.benign:
        outcome = run_scenario(scenario, default_policy())
        expects_confirm = scenario.meta_value("expects") == "confirm"
        assert outcome.utility_ok == (not expects_confirm), scenario.id
        assert outcome.result.blocked == (1 if expects_confirm else 0), scenario.id


def test_confirm_callback_restores_the_confirm_family(suite: Suite) -> None:
    for scenario in suite.benign:
        outcome = run_scenario(scenario, default_policy(), confirm=lambda tool, verdict: True)
        assert outcome.utility_ok, scenario.id
        assert outcome.result.blocked == 0, scenario.id


def test_benign_tasks_work_without_any_defense(suite: Suite) -> None:
    assert all(run_scenario(s, Policy()).utility_ok for s in suite.benign)


def test_benign_runs_never_count_as_attacks(suite: Suite) -> None:
    assert not any(run_scenario(s, Policy()).attack_succeeded for s in suite.benign)
