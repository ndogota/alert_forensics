import pytest
from pydantic import ValidationError

from alert_forensics import validate_grounding
from alert_forensics.artifact import CorrectionRecord, RunArtifact
from alert_forensics.contracts import (
    DispositionDecision,
    HumanDecision,
    ObservedFact,
    RunError,
    RunOutcome,
)
from alert_forensics.repair import (
    CitationRepair,
    CitationRepairs,
    build_repair_instruction,
)
from conftest import with_facts


def test_run_outcome_has_exactly_the_three_spec_values():
    assert [o.value for o in RunOutcome] == ["completed", "failed_ungrounded", "failed_error"]


def make_artifact(trace, report=None, **overrides):
    fields = {
        "investigation_id": "inv-1",
        "outcome": RunOutcome.completed,
        "model": "scripted:demo",
        "output_binding": {
            "strategy": "provider",
            "profile_declared": True,
            "structured_output": True,
        },
        "role": "analyst",
        "adapters": {"search_events": "fixture", "lookup_ioc": "live"},
        "trace": trace,
        "report": report,
        "passes": 1 if report is not None else 0,
        "corrections": [],
        "decisions": [],
        "error": None,
        "raw_store": "run.raw",
    }
    fields.update(overrides)
    return RunArtifact.model_validate(fields)


def test_a_completed_artifact_carries_a_grounded_report_and_round_trips(trace, grounded_result):
    report = validate_grounding(grounded_result, trace)
    artifact = make_artifact(
        trace,
        report,
        decisions=[
            HumanDecision(
                tool_call_id="tc-propose",
                proposal={"verdict": "false_positive", "recommended_action": "Close."},
                decision=DispositionDecision.accepted,
                reason=None,
            )
        ],
    )
    assert artifact.outcome is RunOutcome.completed
    assert artifact.result is grounded_result
    assert RunArtifact.model_validate_json(artifact.model_dump_json()) == artifact


def test_completed_requires_a_grounded_report(trace, grounded_result):
    ungrounded = with_facts(
        grounded_result, [ObservedFact(statement="Invented.", evidence=["tc-nope"])]
    )
    report = validate_grounding(ungrounded, trace)
    with pytest.raises(ValidationError, match="completed"):
        make_artifact(trace, report, outcome=RunOutcome.completed)
    artifact = make_artifact(trace, report, outcome=RunOutcome.failed_ungrounded)
    assert artifact.outcome is RunOutcome.failed_ungrounded
    with pytest.raises(ValidationError, match="failed_ungrounded"):
        make_artifact(trace, None, outcome=RunOutcome.failed_ungrounded, passes=0)


def test_failed_error_carries_the_error_and_no_report(trace, grounded_result):
    error = RunError(kind="ScriptExhausted", message="the script ran out after 3 turns")
    artifact = make_artifact(trace, None, outcome=RunOutcome.failed_error, error=error, passes=0)
    assert artifact.result is None
    with pytest.raises(ValidationError, match="error"):
        make_artifact(trace, None, outcome=RunOutcome.failed_error, passes=0)
    report = validate_grounding(grounded_result, trace)
    with pytest.raises(ValidationError, match="error"):
        make_artifact(trace, report, outcome=RunOutcome.completed, error=error)


def test_a_correction_means_two_passes(trace, grounded_result):
    ungrounded = with_facts(
        grounded_result, [ObservedFact(statement="Invented.", evidence=["tc-nope"])]
    )
    before = validate_grounding(ungrounded, trace)
    correction = CorrectionRecord(
        instruction=build_repair_instruction(before, trace),
        repairs=CitationRepairs(
            repairs=[CitationRepair(index=0, action="recite", evidence=["tc-events"])]
        ),
        report_before=before,
    )
    after = validate_grounding(
        with_facts(grounded_result, [ObservedFact(statement="Invented.", evidence=["tc-events"])]),
        trace,
    )
    artifact = make_artifact(trace, after, passes=2, corrections=[correction])
    assert artifact.passes == 2
    assert artifact.correction == correction
    with pytest.raises(ValidationError, match="passes"):
        make_artifact(trace, after, passes=1, corrections=[correction])
    with pytest.raises(ValidationError, match="passes"):
        make_artifact(trace, after, passes=2, corrections=[])
    with pytest.raises(ValidationError, match="correction"):
        make_artifact(
            trace,
            None,
            outcome=RunOutcome.failed_error,
            passes=0,
            error=RunError(kind="x", message="y"),
            corrections=[correction],
        )


def test_model_limits_sit_beside_the_model_and_round_trip(trace, grounded_result):
    from alert_forensics.contracts import ModelLimits

    report = validate_grounding(grounded_result, trace)
    limits = ModelLimits(timeout_s=60, max_retries=1)
    artifact = make_artifact(trace, report, model_limits=limits)
    assert artifact.model_limits == limits
    assert RunArtifact.model_validate_json(artifact.model_dump_json()) == artifact
    # The scripted client makes no network call: nothing bounded it, and it says so.
    assert make_artifact(trace, report).model_limits is None
    with pytest.raises(ValidationError):
        ModelLimits(timeout_s=0, max_retries=1)
    with pytest.raises(ValidationError):
        ModelLimits(timeout_s=60, max_retries=-1)


def test_the_output_binding_is_required_and_round_trips(trace, grounded_result):
    from alert_forensics.contracts import OutputBinding

    report = validate_grounding(grounded_result, trace)
    binding = OutputBinding(strategy="tool", profile_declared=True, structured_output=False)
    artifact = make_artifact(trace, report, output_binding=binding)
    assert artifact.output_binding == binding
    assert RunArtifact.model_validate_json(artifact.model_dump_json()) == artifact
    fields = artifact.model_dump()
    del fields["output_binding"]
    with pytest.raises(ValidationError, match="output_binding"):
        RunArtifact.model_validate(fields)
    with pytest.raises(ValidationError):
        OutputBinding(strategy="magic", profile_declared=True, structured_output=True)
