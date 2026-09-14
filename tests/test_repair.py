import json

import pytest
from pydantic import ValidationError

from alert_forensics import validate_grounding
from alert_forensics.contracts import (
    Assumption,
    InvestigationTrace,
    ObservedFact,
    SourceSystem,
    ToolOutcome,
)
from alert_forensics.repair import (
    CitationRepair,
    CitationRepairs,
    RepairInstruction,
    apply_repairs,
    build_repair_instruction,
)
from conftest import T0, make_record, with_facts


@pytest.fixture
def ungrounded(grounded_result):
    return with_facts(
        grounded_result,
        [
            ObservedFact(statement="Gateway range.", evidence=["tc-events"]),
            ObservedFact(statement="No detections.", evidence=["tc-invented"]),
            ObservedFact(statement="Splunk shows nothing.", evidence=["tc-siem-denied"]),
            ObservedFact(statement="Two problems.", evidence=["tc-ghost", "tc-siem-denied"]),
        ],
    )


def test_the_instruction_names_offending_citations_and_present_calls(ungrounded, trace):
    report = validate_grounding(ungrounded, trace)
    instruction = build_repair_instruction(report, trace)
    assert isinstance(instruction, RepairInstruction)
    offending = [(o.index, o.evidence_id, o.problem) for o in instruction.offending]
    assert offending == [
        (1, "tc-invented", "unknown_id"),
        (2, "tc-siem-denied", "cites_unsuccessful_call"),
        (3, "tc-ghost", "unknown_id"),
        (3, "tc-siem-denied", "cites_unsuccessful_call"),
    ]
    assert instruction.offending[1].statement == "Splunk shows nothing."
    present = {c.tool_call_id: c for c in instruction.present_calls}
    assert list(present) == ["tc-events", "tc-ioc", "tc-identity"]
    assert "tc-siem-denied" not in present
    assert present["tc-events"].outcome is ToolOutcome.ok
    assert present["tc-events"].tool_name == "search_events"
    assert present["tc-events"].arguments == trace.records[0].arguments


def test_the_instruction_carries_no_grounded_fact_and_no_response(ungrounded, trace):
    report = validate_grounding(ungrounded, trace)
    text = json.dumps(build_repair_instruction(report, trace).model_dump(mode="json"))
    assert "Gateway range." not in text
    assert "redacted_response" not in text and "[REDACTED]" not in text
    assert "raw_response" not in text
    assert "verdict" not in text
    for record in trace.records:
        assert json.dumps(record.redacted_response) not in text


def test_repairs_are_applied_only_to_offending_facts(ungrounded, trace):
    report = validate_grounding(ungrounded, trace)
    repairs = CitationRepairs(
        repairs=[
            CitationRepair(index=0, action="recite", evidence=["tc-ioc"]),  # grounded: ignored
            CitationRepair(index=1, action="recite", evidence=["tc-ioc"]),
            CitationRepair(
                index=2,
                action="withdraw",
                why_unverified="The SIEM search was denied; nothing was observed.",
            ),
            CitationRepair(index=9, action="recite", evidence=["tc-events"]),  # no such fact
        ]
    )
    repaired = apply_repairs(ungrounded, report, repairs)
    assert [f.evidence for f in repaired.observed_facts] == [
        ["tc-events"],
        ["tc-ioc"],
        ["tc-ghost", "tc-siem-denied"],
    ]
    assert [f.statement for f in repaired.observed_facts] == [
        "Gateway range.",
        "No detections.",
        "Two problems.",
    ]
    assert repaired.assumptions[-1] == Assumption(
        statement="Splunk shows nothing.",
        why_unverified="The SIEM search was denied; nothing was observed.",
    )
    assert repaired.assumptions[:-1] == list(ungrounded.assumptions)
    for name in ("verdict", "confidence", "mitre_techniques", "recommended_action", "escalate"):
        assert getattr(repaired, name) == getattr(ungrounded, name)
    assert repaired.missing_context == ungrounded.missing_context
    after = validate_grounding(repaired, trace)
    assert [f.grounded for f in after.facts] == [True, True, False]


def test_a_repair_is_recite_with_evidence_or_withdraw_with_a_reason():
    with pytest.raises(ValidationError):
        CitationRepair(index=0, action="recite", evidence=[])
    with pytest.raises(ValidationError):
        CitationRepair(index=0, action="withdraw")
    with pytest.raises(ValidationError):
        CitationRepair(index=0, action="withdraw", why_unverified="x", evidence=["tc-1"])
    with pytest.raises(ValidationError):
        CitationRepair(index=-1, action="recite", evidence=["tc-1"])


def test_withdrawing_every_fact_cannot_launder_a_verdict(ungrounded, trace, alert):
    only_bad = with_facts(
        ungrounded, [ObservedFact(statement="Invented.", evidence=["tc-invented"])]
    )
    report = validate_grounding(only_bad, trace)
    repaired = apply_repairs(
        only_bad,
        report,
        CitationRepairs(
            repairs=[CitationRepair(index=0, action="withdraw", why_unverified="No such call.")]
        ),
    )
    assert repaired.observed_facts == []
    assert repaired.verdict == only_bad.verdict
    after = validate_grounding(repaired, trace)
    assert after.no_facts and not after.is_grounded
    bare = InvestigationTrace(
        investigation_id="inv-2",
        alert=alert,
        started_at=T0,
        records=[make_record("tc-x", "search_events", SourceSystem.defender)],
    )
    assert not validate_grounding(repaired, bare).is_grounded


def test_present_calls_are_only_those_a_citation_can_succeed_on(alert, ungrounded):
    """A denied call, a failed call, an unknown tool and the proposal are never offered:
    each would be refused by the validator, and the loop has one attempt."""
    records = [
        make_record("tc-ok", "search_events", SourceSystem.defender),
        make_record("tc-denied", "search_siem", SourceSystem.splunk, outcome=ToolOutcome.denied),
        make_record("tc-error", "lookup_ioc", SourceSystem.virustotal, outcome=ToolOutcome.error),
        make_record("tc-nowhere", "no_such_tool", SourceSystem.none, outcome=ToolOutcome.error),
        make_record("tc-propose", "propose_alert_disposition", SourceSystem.human),
        make_record("tc-runbook", "search_runbook", SourceSystem.runbook),
    ]
    trace = InvestigationTrace(
        investigation_id="inv-3", alert=alert, started_at=T0, records=records
    )
    report = validate_grounding(ungrounded, trace)
    instruction = build_repair_instruction(report, trace)
    offered = [c.tool_call_id for c in instruction.present_calls]
    assert offered == ["tc-ok", "tc-runbook"]
    assert all(c.outcome is ToolOutcome.ok for c in instruction.present_calls)
    # Every offered id grounds a fact; every withheld id would not.
    for record in records:
        fact = ObservedFact(statement="Re-cited.", evidence=[record.tool_call_id])
        grounded = validate_grounding(with_facts(ungrounded, [fact]), trace).is_grounded
        assert grounded == (record.tool_call_id in offered), record.tool_call_id


def test_a_trace_with_no_citable_call_offers_nothing(alert, ungrounded):
    trace = InvestigationTrace(
        investigation_id="inv-4",
        alert=alert,
        started_at=T0,
        records=[make_record("tc-propose", "propose_alert_disposition", SourceSystem.human)],
    )
    instruction = build_repair_instruction(validate_grounding(ungrounded, trace), trace)
    assert instruction.present_calls == []
    assert instruction.offending
