import json
from copy import deepcopy

import pytest
from langchain_core.exceptions import ModelRateLimitError
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.utils.function_calling import convert_to_openai_tool

from alert_forensics.agent import AnalystDecision, run_triage, runner_tools
from alert_forensics.agent.run import PROVIDER_REFUSALS, run_error
from alert_forensics.agent.scripted import (
    ScriptedCall,
    ScriptedChatModel,
    StructuredTurn,
    TextTurn,
    ToolCallsTurn,
)
from alert_forensics.contracts import (
    Alert,
    DispositionDecision,
    RunOutcome,
    SourceSystem,
    ToolOutcome,
    Verdict,
)
from alert_forensics.tools import (
    ANALYST_ROLE,
    TIER1_ROLE,
    FixtureSet,
    InMemoryRawStore,
    Principal,
    ToolRunner,
    fixture_adapters,
)
from alert_forensics.tools.disposition import DispositionAdapter
from conftest import ALERT_PAYLOAD, FIXTURE_TOOLS_DIR, T0, RefusingChatModel

PROFILES = {"provider": {"structured_output": True}, "tool": {"structured_output": False}}


def call(id_, name, **args):
    return ScriptedCall(id=id_, name=name, args=args)


INVESTIGATION = ToolCallsTurn(
    tool_calls=[
        call(
            "tc-signins",
            "search_events",
            query=(
                "SigninLogs | where UserPrincipalName == 'jdoe@contoso.com' "
                "| project Timestamp, IPAddress, City"
            ),
        ),
        call("tc-ioc", "lookup_ioc", indicator="203.0.113.7"),
        call("tc-identity", "get_identity", identity="jdoe"),
    ]
)
PROPOSAL = ToolCallsTurn(
    tool_calls=[
        call(
            "tc-propose",
            "propose_alert_disposition",
            verdict="false_positive",
            recommended_action="Close; add the gateway range to the travel allowlist.",
            escalate=False,
            summary="Both sign-ins come from the group SASE gateway.",
        )
    ]
)


def result_turn(*evidence: list[str]):
    statements = ["Both sign-ins originate from the SASE gateway.", "No engine flags the IP."]
    return StructuredTurn(
        payload={
            "verdict": "false_positive",
            "confidence": 0.9,
            "mitre_techniques": ["T1078.004"],
            "observed_facts": [
                {"statement": s, "evidence": e} for s, e in zip(statements, evidence, strict=True)
            ],
            "assumptions": [],
            "missing_context": [
                {
                    "what": "VPN session log",
                    "why_it_matters": "Confirms the gateway directly.",
                    "how_to_obtain": "SASE audit log.",
                }
            ],
            "recommended_action": "Close; add the gateway range to the travel allowlist.",
            "escalate": False,
        }
    )


def repairs_turn(*repairs):
    return StructuredTurn(payload={"repairs": list(repairs)})


@pytest.fixture(scope="module")
def fixture_set():
    return FixtureSet.load(FIXTURE_TOOLS_DIR)


def run(
    script,
    *,
    fixture_set,
    profile="provider",
    role=ANALYST_ROLE,
    decide=None,
    max_corrections=1,
    alert=None,
    recursion_limit=50,
):
    model = ScriptedChatModel(script=script, profile=PROFILES[profile], model_id="scripted:test")
    store = InMemoryRawStore()
    artifact = run_triage(
        alert=alert or Alert.model_validate(ALERT_PAYLOAD),
        model=model,
        model_id="scripted:test",
        principal=Principal(name="analyst", role=role),
        adapters=[*fixture_adapters(fixture_set), DispositionAdapter(clock=lambda: T0)],
        store=store,
        raw_store="mem",
        decide=decide or (lambda proposal: AnalystDecision(accept=True)),
        investigation_id="inv-graph",
        max_corrections=max_corrections,
        clock=lambda: T0,
        recursion_limit=recursion_limit,
    )
    return artifact, model, store


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_a_completed_run_journals_every_call_and_grounds_the_result(fixture_set, profile):
    script = [INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, _, store = run(script, fixture_set=fixture_set, profile=profile)
    assert artifact.outcome is RunOutcome.completed
    assert artifact.passes == 1 and artifact.correction is None and artifact.error is None
    assert artifact.model == "scripted:test" and artifact.role == "analyst"
    records = artifact.trace.records
    assert [r.tool_call_id for r in records] == [
        "tc-signins",
        "tc-ioc",
        "tc-identity",
        "tc-propose",
    ]
    assert [r.step for r in records] == [0, 0, 0, 1]
    assert [r.outcome for r in records] == [ToolOutcome.ok] * 4
    assert records[3].source_system is SourceSystem.human
    assert records[3].caller == "analyst"
    for record in records:
        assert store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256)
    report = artifact.report
    assert report is not None and report.is_grounded
    assert report.result.verdict is Verdict.false_positive
    assert [f.source_systems for f in report.facts] == [
        [SourceSystem.defender],
        [SourceSystem.virustotal],
    ]
    assert [u.step for u in artifact.trace.usage] == [0, 1, 2]
    assert {u.model for u in artifact.trace.usage} == {"scripted:test"}
    assert artifact.decisions[0].decision is DispositionDecision.accepted
    assert artifact.decisions[0].tool_call_id == "tc-propose"
    assert artifact.decisions[0].proposal["verdict"] == "false_positive"
    assert artifact.adapters["search_events"] == "fixture"
    assert artifact.adapters["propose_alert_disposition"] == "local"
    assert artifact.trace.investigation_id == "inv-graph"
    assert artifact.trace.alert.id == ALERT_PAYLOAD["id"]


def test_the_model_sees_the_redacted_response_verbatim_and_nothing_raw(fixture_set):
    script = [INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, model, store = run(script, fixture_set=fixture_set)
    second_turn = model.received[1]
    tool_messages = {m.tool_call_id: m for m in second_turn if isinstance(m, ToolMessage)}
    for record in artifact.trace.records[:3]:
        message = tool_messages[record.tool_call_id]
        assert json.loads(str(message.content)) == record.redacted_response
        raw = store.get(record.raw_response_ref)
        assert json.dumps(raw, sort_keys=True) != json.dumps(
            record.redacted_response, sort_keys=True
        )
    everything = json.dumps([m.model_dump() for turn in model.received for m in turn])
    assert "last_analysis_results" not in everything
    assert "+31 20" not in everything


def test_the_alert_is_redacted_before_the_model_sees_it(fixture_set):
    payload = deepcopy(ALERT_PAYLOAD)
    payload["evidence"][0]["userAccount"]["displayName"] = "Jane Q. Doe"
    script = [INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, model, _ = run(script, fixture_set=fixture_set, alert=Alert.model_validate(payload))
    first = model.received[0]
    assert isinstance(first[0], SystemMessage) and isinstance(first[1], HumanMessage)
    assert "Jane Q. Doe" not in str(first[1].content)
    assert "jdoe@contoso.com" in str(first[1].content)
    assert ALERT_PAYLOAD["id"] in str(first[1].content)
    # The archived alert keeps the name: redaction is a projection, not a destruction.
    assert "Jane Q. Doe" in artifact.trace.model_dump_json()


def test_wrong_arguments_reach_the_journal_as_invalid_arguments(fixture_set):
    bad = ToolCallsTurn(tool_calls=[call("tc-bad", "lookup_ioc", ioc="203.0.113.7")])
    script = [bad, INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, _, _ = run(script, fixture_set=fixture_set)
    assert artifact.outcome is RunOutcome.completed
    record = artifact.trace.find("tc-bad")
    assert record is not None and record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "invalid_arguments"
    assert record.step == 0
    assert artifact.trace.find("tc-signins").step == 1


def test_a_rejected_proposal_is_not_run_and_the_model_is_told(fixture_set):
    seen = []

    def decide(proposal):
        seen.append(proposal)
        return AnalystDecision(accept=False, reason="Not until the VPN log is checked.")

    script = [INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, model, _ = run(script, fixture_set=fixture_set, decide=decide)
    assert artifact.outcome is RunOutcome.completed
    assert artifact.trace.find("tc-propose") is None
    assert len(seen) == 1 and seen[0]["verdict"] == "false_positive"
    decision = artifact.decisions[0]
    assert decision.decision is DispositionDecision.rejected
    assert decision.reason == "Not until the VPN log is checked."
    assert decision.tool_call_id == "tc-propose"
    told = [m for m in model.received[2] if isinstance(m, ToolMessage)][-1]
    assert told.tool_call_id == "tc-propose"
    assert "rejected" in str(told.content) and "VPN log" in str(told.content)


def test_read_only_tools_never_interrupt(fixture_set):
    calls = []
    script = [INVESTIGATION, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, _, _ = run(
        script,
        fixture_set=fixture_set,
        decide=lambda p: calls.append(p) or AnalystDecision(accept=True),
    )
    assert artifact.outcome is RunOutcome.completed
    assert calls == [] and artifact.decisions == []


def test_a_tier1_proposal_is_denied_even_when_the_human_accepts(fixture_set):
    script = [INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, _, _ = run(script, fixture_set=fixture_set, role=TIER1_ROLE)
    assert artifact.outcome is RunOutcome.completed
    assert artifact.decisions[0].decision is DispositionDecision.accepted
    record = artifact.trace.find("tc-propose")
    assert record is not None and record.outcome is ToolOutcome.denied
    assert record.required_scope == "alerts:write"
    assert artifact.role == "tier1"


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_the_correction_loop_repairs_an_invented_citation(fixture_set, profile):
    script = [
        INVESTIGATION,
        PROPOSAL,
        result_turn(["tc-invented"], ["tc-ioc"]),
        repairs_turn({"index": 0, "action": "recite", "evidence": ["tc-signins"]}),
    ]
    artifact, model, _ = run(script, fixture_set=fixture_set, profile=profile)
    assert artifact.outcome is RunOutcome.completed
    assert artifact.passes == 2
    correction = artifact.correction
    assert correction is not None
    assert not correction.report_before.is_grounded
    offending = [(o.index, o.evidence_id, o.problem) for o in correction.instruction.offending]
    assert offending == [(0, "tc-invented", "unknown_id")]
    assert [c.tool_call_id for c in correction.instruction.present_calls] == [
        "tc-signins",
        "tc-ioc",
        "tc-identity",
        "tc-propose",
    ]
    report = artifact.report
    assert report.is_grounded
    assert [f.evidence_ids for f in report.facts] == [["tc-signins"], ["tc-ioc"]]
    assert report.result.verdict is Verdict.false_positive
    assert report.result.confidence == 0.9
    # The repair pass is a fresh call: a system prompt and the instruction, nothing else.
    repair_turn = model.received[3]
    assert [type(m) for m in repair_turn] == [SystemMessage, HumanMessage]
    instruction = str(repair_turn[1].content)
    assert "tc-invented" in instruction and "tc-signins" in instruction
    assert "No engine flags the IP." not in instruction
    assert "detection_ratio" not in instruction and "redacted" not in instruction
    assert [u.step for u in artifact.trace.usage] == [0, 1, 2, 3]


def test_a_correction_that_still_fails_is_failed_ungrounded_never_inconclusive(fixture_set):
    script = [
        INVESTIGATION,
        PROPOSAL,
        result_turn(["tc-invented"], ["tc-ioc"]),
        repairs_turn({"index": 0, "action": "recite", "evidence": ["tc-still-invented"]}),
    ]
    artifact, model, _ = run(script, fixture_set=fixture_set)
    assert artifact.outcome is RunOutcome.failed_ungrounded
    assert artifact.passes == 2
    assert artifact.correction is not None
    assert not artifact.report.is_grounded
    assert artifact.report.result.verdict is Verdict.false_positive
    assert artifact.report.facts[0].problems[0].evidence_id == "tc-still-invented"
    assert len(model.received) == 4


def test_withdrawing_the_only_facts_is_still_a_failure(fixture_set):
    script = [
        INVESTIGATION,
        PROPOSAL,
        result_turn(["tc-invented"], ["tc-ghost"]),
        repairs_turn(
            {"index": 0, "action": "withdraw", "why_unverified": "No such call."},
            {"index": 1, "action": "withdraw", "why_unverified": "No such call."},
        ),
    ]
    artifact, _, _ = run(script, fixture_set=fixture_set)
    assert artifact.outcome is RunOutcome.failed_ungrounded
    assert artifact.report.no_facts
    assert artifact.report.result.verdict is Verdict.false_positive
    assert len(artifact.report.result.assumptions) == 2


def test_zero_corrections_means_one_pass(fixture_set):
    script = [INVESTIGATION, PROPOSAL, result_turn(["tc-invented"], ["tc-ioc"])]
    artifact, model, _ = run(script, fixture_set=fixture_set, max_corrections=0)
    assert artifact.outcome is RunOutcome.failed_ungrounded
    assert artifact.passes == 1 and artifact.correction is None
    assert len(model.received) == 3


def test_an_exhausted_script_is_failed_error_with_the_trace_so_far(fixture_set):
    artifact, _, _ = run([INVESTIGATION], fixture_set=fixture_set)
    assert artifact.outcome is RunOutcome.failed_error
    assert artifact.report is None and artifact.passes == 0
    assert artifact.error is not None and artifact.error.kind == "ScriptExhaustedError"
    assert [r.tool_call_id for r in artifact.trace.records] == [
        "tc-signins",
        "tc-ioc",
        "tc-identity",
    ]
    assert len(artifact.trace.usage) == 1


def test_a_run_over_budget_is_failed_error(fixture_set):
    script = [INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])]
    artifact, _, _ = run(script, fixture_set=fixture_set, recursion_limit=2)
    assert artifact.outcome is RunOutcome.failed_error
    assert artifact.error.kind == "budget"


def test_a_model_that_answers_in_prose_produced_no_result(fixture_set):
    script = [INVESTIGATION, TextTurn(text="It looks benign to me.")]
    artifact, _, _ = run(script, fixture_set=fixture_set, profile="tool")
    assert artifact.outcome is RunOutcome.failed_error
    assert artifact.error.kind == "no_result"
    assert len(artifact.trace.records) == 3


def test_runner_tools_expose_the_request_schema_and_journal_through_the_runner(fixture_set):
    runner = ToolRunner(
        adapters=[*fixture_adapters(fixture_set), DispositionAdapter(clock=lambda: T0)],
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id="inv-tools",
        clock=lambda: T0,
    )
    tools = {t.name: t for t in runner_tools(runner)}
    assert list(tools) == [
        "search_events",
        "search_siem",
        "get_identity",
        "get_asset",
        "lookup_ioc",
        "get_related_alerts",
        "get_process_tree",
        "search_runbook",
        "get_attack_technique",
        "propose_alert_disposition",
    ]
    schema = convert_to_openai_tool(tools["lookup_ioc"])["function"]["parameters"]
    assert "indicator" in schema["properties"]
    assert "runtime" not in schema["properties"]
    assert schema["required"] == ["indicator"]
    assert tools["lookup_ioc"].description.startswith(
        runner.adapters["lookup_ioc"].definition.description[:40]
    )
    # Only registered adapters are offered.
    partial = ToolRunner(
        adapters=fixture_adapters(fixture_set)[:2],
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id="inv-partial",
    )
    assert [t.name for t in runner_tools(partial)] == ["search_events", "search_siem"]


# --- Bounded model calls, progress, provider refusals --------------------------------


def test_the_runner_callback_sees_every_call_of_a_run(fixture_set):
    seen = []
    model = ScriptedChatModel(
        script=[INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])],
        profile=PROFILES["provider"],
        model_id="s:t",
    )
    artifact = run_triage(
        alert=Alert.model_validate(ALERT_PAYLOAD),
        model=model,
        model_id="s:t",
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        adapters=[*fixture_adapters(fixture_set), DispositionAdapter(clock=lambda: T0)],
        store=InMemoryRawStore(),
        raw_store="mem",
        decide=lambda proposal: AnalystDecision(accept=True),
        clock=lambda: T0,
        on_tool_call=seen.append,
    )
    assert artifact.outcome is RunOutcome.completed
    assert seen == artifact.trace.records
    assert artifact.model_limits is None


def test_model_limits_are_recorded_when_given(fixture_set):
    from alert_forensics.contracts import ModelLimits

    limits = ModelLimits(timeout_s=30, max_retries=2)
    artifact, _, _ = run(
        [INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])], fixture_set=fixture_set
    )
    assert artifact.model_limits is None
    model = ScriptedChatModel(
        script=[INVESTIGATION, PROPOSAL, result_turn(["tc-signins"], ["tc-ioc"])],
        profile=PROFILES["provider"],
        model_id="s:t",
    )
    artifact = run_triage(
        alert=Alert.model_validate(ALERT_PAYLOAD),
        model=model,
        model_id="s:t",
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        adapters=[*fixture_adapters(fixture_set), DispositionAdapter(clock=lambda: T0)],
        store=InMemoryRawStore(),
        raw_store="mem",
        decide=lambda proposal: AnalystDecision(accept=True),
        clock=lambda: T0,
        model_limits=limits,
    )
    assert artifact.model_limits == limits


class _StatusError(Exception):
    def __init__(self, status_code: int, message: str = "nope"):
        super().__init__(message)
        self.status_code = status_code


@pytest.mark.parametrize(
    ("exc", "kind"),
    [
        (ModelRateLimitError("Error calling model 'g' (RESOURCE_EXHAUSTED): 429"), "rate_limit"),
        (_StatusError(429), "rate_limit"),
        (_StatusError(503), "overloaded"),
        (_StatusError(529, "overloaded_error"), "overloaded"),
        (
            Exception(
                "503 UNAVAILABLE. {'error': {'code': 503, 'message': 'This model is "
                "currently experiencing high demand.', 'status': 'UNAVAILABLE'}}"
            ),
            "overloaded",
        ),
        (Exception("429 RESOURCE_EXHAUSTED. quota exceeded for quota metric"), "rate_limit"),
        (RuntimeError("You exceeded your current quota, please check your plan"), "rate_limit"),
        (ValueError("boom"), "ValueError"),
        (_StatusError(500, "internal"), "_StatusError"),
    ],
)
def test_a_provider_refusal_is_classified_by_class_then_status_then_message(exc, kind):
    error = run_error(exc)
    assert error.kind == kind
    assert error.message == str(exc)
    assert (kind in PROVIDER_REFUSALS) == (kind in {"rate_limit", "overloaded"})


def test_a_refused_run_is_failed_error_of_kind_rate_limit_and_still_writes_the_trace(
    fixture_set,
):
    model = RefusingChatModel(exc=ModelRateLimitError("429 RESOURCE_EXHAUSTED"))
    artifact = run_triage(
        alert=Alert.model_validate(ALERT_PAYLOAD),
        model=model,
        model_id="google_genai:gemini-x",
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        adapters=[*fixture_adapters(fixture_set), DispositionAdapter(clock=lambda: T0)],
        store=InMemoryRawStore(),
        raw_store="mem",
        decide=lambda proposal: AnalystDecision(accept=True),
        clock=lambda: T0,
    )
    assert artifact.outcome is RunOutcome.failed_error
    assert artifact.error.kind == "rate_limit"
    assert "429" in artifact.error.message
    assert artifact.trace.records == []
