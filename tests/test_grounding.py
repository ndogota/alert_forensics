import pytest
from pydantic import ValidationError

import alert_forensics
from alert_forensics import GroundingReport, validate_grounding
from alert_forensics.contracts import (
    Assumption,
    InvestigationTrace,
    MissingContext,
    ObservedFact,
    SourceSystem,
    ToolOutcome,
    TriageResult,
    Verdict,
)
from conftest import make_record, with_facts


def fact(evidence: list[str]) -> ObservedFact:
    return ObservedFact(statement="a claim", evidence=evidence)


def test_fully_grounded_result_has_zero_rate(grounded_result, trace):
    report = validate_grounding(grounded_result, trace)
    assert report.is_grounded
    assert report.ungrounded_claim_rate == 0.0
    assert report.total_facts == 3
    assert report.grounded_count == 3
    assert report.ungrounded_count == 0
    assert not report.no_facts
    assert all(f.grounded and not f.problems for f in report.facts)
    assert report.ungrounded_facts == []
    assert [f.index for f in report.grounded_facts] == [0, 1, 2]
    assert [f.source_systems for f in report.facts] == [
        [SourceSystem.defender],
        [SourceSystem.virustotal],
        [SourceSystem.splunk],
    ]


def test_unknown_id_is_flagged(grounded_result, trace):
    result = with_facts(grounded_result, [*grounded_result.observed_facts, fact(["tc-nope"])])
    report = validate_grounding(result, trace)
    assert not report.is_grounded
    assert report.ungrounded_claim_rate == pytest.approx(1 / 4)
    bad = report.facts[3]
    assert not bad.grounded
    assert bad.resolved_ids == []
    assert [(p.evidence_id, p.kind) for p in bad.problems] == [("tc-nope", "unknown_id")]


def test_fact_correlating_two_source_systems_is_grounded(grounded_result, trace):
    # A defender call and a splunk call cited by one fact is a correlation, not a defect.
    result = with_facts(grounded_result, [fact(["tc-events", "tc-identity"])])
    report = validate_grounding(result, trace)
    assert report.is_grounded
    only = report.facts[0]
    assert only.grounded
    assert only.problems == []
    assert only.source_systems == [SourceSystem.defender, SourceSystem.splunk]


def test_source_systems_live_only_on_the_report():
    # The fact carries no source system, declared or derived; the report is the one place.
    assert set(ObservedFact.model_fields) == {"statement", "evidence"}
    assert set(TriageResult.model_json_schema()["$defs"]["ObservedFact"]["properties"]) == {
        "statement",
        "evidence",
    }
    with pytest.raises(ValidationError):
        ObservedFact.model_validate(
            {"statement": "s", "evidence": ["tc-events"], "source_systems": ["defender"]}
        )
    with pytest.raises(ValidationError):
        ObservedFact.model_validate(
            {"statement": "s", "evidence": ["tc-events"], "source_system": "defender"}
        )
    assert not hasattr(alert_forensics, "attach_source_systems")


def test_denied_call_cannot_support_a_fact(grounded_result, trace):
    result = with_facts(grounded_result, [fact(["tc-siem-denied"])])
    report = validate_grounding(result, trace)
    assert not report.is_grounded
    assert [p.kind for p in report.facts[0].problems] == ["cites_unsuccessful_call"]
    assert "denied" in report.facts[0].problems[0].detail


def test_errored_call_cannot_support_a_fact(grounded_result, trace):
    errored = trace.model_copy(
        update={
            "records": [
                *trace.records,
                make_record(
                    "tc-err", "get_asset", SourceSystem.splunk, step=2, outcome=ToolOutcome.error
                ),
            ]
        }
    )
    result = with_facts(grounded_result, [fact(["tc-err"])])
    report = validate_grounding(result, errored)
    assert [p.kind for p in report.facts[0].problems] == ["cites_unsuccessful_call"]


def test_empty_evidence_is_rejected_at_schema_level():
    with pytest.raises(ValidationError):
        ObservedFact(statement="x", evidence=[])
    with pytest.raises(ValidationError):
        ObservedFact(statement="x", evidence=[""])
    with pytest.raises(ValidationError):
        ObservedFact(statement="x", evidence=["   "])


def test_assumptions_and_missing_context_are_exempt(grounded_result, trace):
    result = grounded_result.model_copy(
        update={
            "assumptions": [
                Assumption(statement="cites nothing", why_unverified="by design"),
                Assumption(statement="mentions tc-nope", why_unverified="still not evidence"),
            ],
            "missing_context": [
                MissingContext(what="tc-nope", why_it_matters="n/a", how_to_obtain="n/a"),
            ],
        }
    )
    report = validate_grounding(result, trace)
    assert report.is_grounded
    assert report.total_facts == 3


def test_duplicate_ids_do_not_inflate_the_count(grounded_result, trace):
    missing_twice = fact(["tc-nope", "tc-nope"])
    valid_twice = fact(["tc-events", "tc-events"])
    report = validate_grounding(with_facts(grounded_result, [missing_twice, valid_twice]), trace)
    assert report.total_facts == 2
    assert report.ungrounded_count == 1
    assert report.ungrounded_claim_rate == 0.5
    assert report.facts[0].evidence_ids == ["tc-nope"]
    assert len(report.facts[0].problems) == 1
    assert report.facts[1].grounded
    assert report.facts[1].evidence_ids == ["tc-events"]
    assert report.facts[1].resolved_ids == ["tc-events"]


def test_one_bad_id_ungrounds_the_whole_fact(grounded_result, trace):
    mixed = fact(["tc-events", "tc-nope"])
    report = validate_grounding(with_facts(grounded_result, [mixed]), trace)
    only = report.facts[0]
    assert not only.grounded
    assert only.evidence_ids == ["tc-events", "tc-nope"]
    assert only.resolved_ids == ["tc-events"]
    assert [p.evidence_id for p in only.problems] == ["tc-nope"]


def test_silence_with_an_asserting_verdict_is_not_grounded(grounded_result, trace):
    silent = with_facts(grounded_result, [])
    assert silent.verdict is Verdict.false_positive
    report = validate_grounding(silent, trace)
    assert report.no_facts
    assert report.total_facts == 0
    assert not report.is_grounded
    assert report.ungrounded_claim_rate == 1.0
    assert report.facts == []


def test_inconclusive_silence_that_names_missing_context_is_grounded(grounded_result, trace):
    silent = with_facts(grounded_result, []).model_copy(update={"verdict": Verdict.inconclusive})
    assert len(silent.missing_context) == 1
    report = validate_grounding(silent, trace)
    assert report.no_facts
    assert report.missing_context_count == 1
    assert report.is_grounded
    assert report.ungrounded_claim_rate == 0.0


def test_inconclusive_silence_that_names_nothing_is_not_grounded(grounded_result, trace):
    empty = with_facts(grounded_result, []).model_copy(
        update={"verdict": Verdict.inconclusive, "missing_context": [], "assumptions": []}
    )
    report = validate_grounding(empty, trace)
    assert report.no_facts
    assert report.missing_context_count == 0
    assert not report.is_grounded
    assert report.ungrounded_claim_rate == 1.0


def test_assumptions_do_not_rescue_inconclusive_silence(grounded_result, trace):
    empty = with_facts(grounded_result, []).model_copy(
        update={"verdict": Verdict.inconclusive, "missing_context": []}
    )
    assert len(empty.assumptions) == 1
    assert not validate_grounding(empty, trace).is_grounded


def test_missing_context_does_not_rescue_an_asserting_verdict(grounded_result, trace):
    for verdict in (Verdict.true_positive, Verdict.false_positive, Verdict.benign_true_positive):
        silent = with_facts(grounded_result, []).model_copy(update={"verdict": verdict})
        assert len(silent.missing_context) == 1
        report = validate_grounding(silent, trace)
        assert not report.is_grounded
        assert report.ungrounded_claim_rate == 1.0


def test_missing_context_does_not_change_a_result_with_facts(grounded_result, trace):
    stripped = grounded_result.model_copy(update={"missing_context": []})
    assert validate_grounding(stripped, trace).is_grounded
    bad = with_facts(grounded_result, [fact(["tc-nope"])])
    assert not validate_grounding(bad, trace).is_grounded


def test_inconclusive_with_ungrounded_facts_is_still_ungrounded(grounded_result, trace):
    result = with_facts(grounded_result, [fact(["tc-nope"])]).model_copy(
        update={"verdict": Verdict.inconclusive}
    )
    report = validate_grounding(result, trace)
    assert not report.no_facts
    assert not report.is_grounded
    assert report.ungrounded_claim_rate == 1.0


def test_lying_report_is_rejected(grounded_result, trace):
    honest = validate_grounding(with_facts(grounded_result, [fact(["tc-nope"])]), trace)
    payload = honest.model_dump()
    for field, lie in (
        ("is_grounded", True),
        ("ungrounded_claim_rate", 0.0),
        ("grounded_count", 1),
        ("ungrounded_count", 0),
        ("total_facts", 2),
        ("no_facts", True),
    ):
        with pytest.raises(ValidationError, match=field):
            GroundingReport.model_validate({**payload, field: lie})
    # Silence dressed up as grounded is caught too, in both its forms.
    silent = validate_grounding(with_facts(grounded_result, []), trace).model_dump()
    with pytest.raises(ValidationError, match="is_grounded"):
        GroundingReport.model_validate({**silent, "is_grounded": True})
    empty = with_facts(grounded_result, []).model_copy(
        update={"verdict": Verdict.inconclusive, "missing_context": []}
    )
    # Claiming missing context that was never named flips the silence rules, so it is caught.
    empty_payload = validate_grounding(empty, trace).model_dump()
    with pytest.raises(ValidationError, match="is_grounded"):
        GroundingReport.model_validate({**empty_payload, "missing_context_count": 1})
    assert GroundingReport.model_validate(payload) == honest


def test_validator_does_not_mutate_inputs(grounded_result, trace):
    before_result = grounded_result.model_dump_json()
    before_trace = trace.model_dump_json()
    validate_grounding(grounded_result, trace)
    assert grounded_result.model_dump_json() == before_result
    assert trace.model_dump_json() == before_trace


def test_report_serialises(grounded_result, trace):
    report = validate_grounding(grounded_result, trace)
    assert type(report).model_validate_json(report.model_dump_json()) == report


def test_validator_is_deterministic(grounded_result: TriageResult, trace: InvestigationTrace):
    a = validate_grounding(grounded_result, trace)
    b = validate_grounding(grounded_result, trace)
    assert a == b
