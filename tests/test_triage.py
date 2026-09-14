import pytest
from pydantic import ValidationError

from alert_forensics.contracts import ObservedFact, TriageResult, Verdict


def test_verdict_has_four_values():
    assert {v.value for v in Verdict} == {
        "true_positive",
        "false_positive",
        "benign_true_positive",
        "inconclusive",
    }


def test_round_trip(grounded_result):
    assert TriageResult.model_validate_json(grounded_result.model_dump_json()) == grounded_result


def test_confidence_bounds(grounded_result):
    payload = grounded_result.model_dump()
    for bad in (-0.1, 1.1):
        with pytest.raises(ValidationError):
            TriageResult.model_validate({**payload, "confidence": bad})


def test_source_systems_is_closed_and_defaults_empty(grounded_result):
    payload = grounded_result.model_dump()
    assert payload["observed_facts"][0]["source_systems"] == []
    payload["observed_facts"][0]["source_systems"] = ["crowdstrike"]
    with pytest.raises(ValidationError):
        TriageResult.model_validate(payload)


def test_mitre_pattern_on_result(grounded_result):
    payload = grounded_result.model_dump()
    payload["mitre_techniques"] = ["T1110.003", "bogus"]
    with pytest.raises(ValidationError):
        TriageResult.model_validate(payload)


def test_unknown_fields_are_rejected(grounded_result):
    payload = grounded_result.model_dump()
    payload["summary"] = "free prose"
    with pytest.raises(ValidationError):
        TriageResult.model_validate(payload)


def test_evidence_dupes_are_tolerated_at_schema_level():
    f = ObservedFact(statement="s", evidence=["a", "a"])
    assert f.evidence == ["a", "a"]
    assert f.source_systems == []
