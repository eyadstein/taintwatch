from taintwatch.agent import (
    Finish,
    Observation,
    PlanStep,
    ScriptedAgent,
    Status,
    ToolRequest,
    render_directive,
)
from taintwatch.labels import Integrity, Label
from taintwatch.spans import TStr

BAD = Label(Integrity.UNTRUSTED, sources=frozenset({"web"}))
GOOD = Label(Integrity.USER, sources=frozenset({"user"}))


def test_plan_order_and_templates() -> None:
    agent = ScriptedAgent(
        [PlanStep("a.one", {"x": "{task}"}), PlanStep("a.two", {"y": "got {r0}"})],
        answer="end {r1}",
    )
    task = TStr.of("T", GOOD)
    first = agent.decide(task, [])
    assert isinstance(first, ToolRequest)
    assert first.tool == "a.one"
    assert first.args["x"].text == "T"
    assert first.args["x"].label_at(0) == GOOD

    obs0 = Observation("a.one", TStr.of("R0", BAD), Status.OK)
    second = agent.decide(task, [obs0])
    assert isinstance(second, ToolRequest)
    assert second.args["y"].text == "got R0"
    assert second.args["y"].label_at(4) == BAD

    obs1 = Observation("a.two", TStr.of("R1"), Status.OK)
    done = agent.decide(task, [obs0, obs1])
    assert isinstance(done, Finish)
    assert done.answer.text == "end R1"


def test_gullible_agent_obeys_directives_before_continuing() -> None:
    agent = ScriptedAgent([PlanStep("a.one", {}), PlanStep("a.two", {})])
    task = TStr.of("t")
    agent.decide(task, [])
    text = TStr.of(render_directive("b.inject", {"v": "1"}), BAD)
    obs = Observation("a.one", text, Status.OK)
    nxt = agent.decide(task, [obs])
    assert isinstance(nxt, ToolRequest)
    assert nxt.tool == "b.inject"
    assert nxt.args["v"].overall_label() == BAD


def test_careful_agent_ignores_directives() -> None:
    agent = ScriptedAgent([PlanStep("a.one", {})], gullible=False)
    task = TStr.of("t")
    agent.decide(task, [])
    text = TStr.of(render_directive("b.inject", {"v": "1"}), BAD)
    nxt = agent.decide(task, [Observation("a.one", text, Status.OK)])
    assert isinstance(nxt, Finish)


def test_blocked_observations_are_not_obeyed() -> None:
    agent = ScriptedAgent([PlanStep("a.one", {})])
    task = TStr.of("t")
    agent.decide(task, [])
    text = TStr.of(render_directive("b.inject", {"v": "1"}), BAD)
    nxt = agent.decide(task, [Observation("a.one", text, Status.BLOCKED)])
    assert isinstance(nxt, Finish)


def test_unresolved_placeholders_are_left_alone() -> None:
    agent = ScriptedAgent([PlanStep("a.one", {})])
    task = TStr.of("t")
    agent.decide(task, [])
    text = TStr.of(render_directive("b.two", {"v": "{r9}"}), BAD)
    nxt = agent.decide(task, [Observation("a.one", text, Status.OK)])
    assert isinstance(nxt, ToolRequest)
    assert nxt.args["v"].text == "{r9}"
