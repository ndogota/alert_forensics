import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from alert_forensics.contracts import (
    Alert,
    InvestigationTrace,
    ModelUsageRecord,
    SourceSystem,
    ToolCallRecord,
    ToolOutcome,
    UnknownEvidence,
    hash_raw_response,
)
from conftest import ALERT_PAYLOAD, MINIMAL_ALERT_PAYLOAD, T0, make_record


def test_trace_round_trips_through_json(trace):
    dumped = trace.model_dump_json()
    parsed = InvestigationTrace.model_validate_json(dumped)
    assert parsed == trace
    assert parsed.model_dump() == trace.model_dump()
    # The Paris offset survives as an instant and as an offset.
    assert parsed.records[1].started_at == trace.records[1].started_at
    assert parsed.records[1].started_at.utcoffset() == trace.records[1].started_at.utcoffset()
    # Microseconds survive.
    assert parsed.started_at.microsecond == 123456
    # Unknown alert fields and unknown evidence survive intact.
    assert parsed.alert.model_extra == {"someFutureField": {"nested": [1, 2, 3]}}
    unknown = parsed.alert.evidence[2]
    assert isinstance(unknown, UnknownEvidence)
    assert unknown.odata_type == "#microsoft.graph.security.registryValueEvidence"
    assert unknown.model_extra == {
        "registryKey": "HKLM\\Software\\Example",
        "registryValueName": "Run",
        "nested": {"a": [1, {"b": None}]},
    }


def test_second_serialisation_is_byte_identical(trace):
    first = trace.model_dump_json()
    second = InvestigationTrace.model_validate_json(first).model_dump_json()
    assert first == second
    assert first.encode("utf-8") == second.encode("utf-8")


def test_json_payloads_keep_their_types(trace):
    data = json.loads(trace.model_dump_json())
    rows = data["records"][0]["redacted_response"]["rows"]
    assert rows == [1, 2.5, "x", None]
    assert isinstance(rows[0], int)
    assert isinstance(rows[1], float)
    assert isinstance(data["records"][0]["duration_us"], int)
    assert data["records"][3]["outcome"] == "denied"
    assert data["usage"][0]["input_token_details"]["cache_read"] == 1000


def test_archived_alert_keeps_only_the_keys_it_was_given(alert):
    minimal = InvestigationTrace(
        investigation_id="inv-min",
        alert=Alert.model_validate(MINIMAL_ALERT_PAYLOAD),
        started_at=T0,
    )
    archived = json.loads(minimal.model_dump_json())["alert"]
    assert set(archived) == set(MINIMAL_ALERT_PAYLOAD)
    assert set(archived["evidence"][0]) == set(MINIMAL_ALERT_PAYLOAD["evidence"][0])
    assert minimal.model_dump()["alert"].keys() == MINIMAL_ALERT_PAYLOAD.keys()
    # The richer fixture is archived with exactly its own keys as well.
    full = json.loads(
        InvestigationTrace(
            investigation_id="inv-full", alert=alert, started_at=T0
        ).model_dump_json()
    )["alert"]
    assert set(full) == set(ALERT_PAYLOAD)
    for got, sent in zip(full["evidence"], ALERT_PAYLOAD["evidence"], strict=True):
        assert set(got) == set(sent)


def test_denied_call_records_caller_and_missing_scope(trace):
    denied = trace.find("tc-siem-denied")
    assert denied is not None
    assert denied.outcome is ToolOutcome.denied
    assert denied.caller == "analyst"
    assert denied.required_scope == "siem:raw_search"
    archived = json.loads(trace.model_dump_json())["records"][3]
    assert archived["caller"] == "analyst"
    assert archived["required_scope"] == "siem:raw_search"


def test_caller_and_scope_are_required(trace):
    payload = trace.records[0].model_dump()
    for field in ("caller", "required_scope"):
        without = {k: v for k, v in payload.items() if k != field}
        with pytest.raises(ValidationError, match=field):
            ToolCallRecord.model_validate(without)
        with pytest.raises(ValidationError, match=field):
            ToolCallRecord.model_validate({**payload, field: "  "})


def test_duplicate_tool_call_id_is_rejected(alert):
    with pytest.raises(ValidationError, match="duplicate tool_call_id"):
        InvestigationTrace(
            investigation_id="inv-dup",
            alert=alert,
            started_at=T0,
            records=[
                make_record("tc-1", "search_events", SourceSystem.defender),
                make_record("tc-1", "lookup_ioc", SourceSystem.virustotal),
            ],
        )


def test_duplicate_usage_step_is_rejected(alert):
    usage = ModelUsageRecord(step=0, model="m", input_tokens=1, output_tokens=1, total_tokens=2)
    with pytest.raises(ValidationError, match="duplicate usage step"):
        InvestigationTrace(
            investigation_id="inv-dup", alert=alert, started_at=T0, usage=[usage, usage]
        )


def test_naive_datetime_is_rejected(trace):
    payload = trace.records[0].model_dump()
    payload["started_at"] = datetime(2026, 1, 1)
    with pytest.raises(ValidationError):
        ToolCallRecord.model_validate(payload)


def test_float_duration_is_rejected(trace):
    payload = trace.records[0].model_dump()
    payload["duration_us"] = 1500.0
    with pytest.raises(ValidationError):
        ToolCallRecord.model_validate(payload)
    payload["duration_us"] = -1
    with pytest.raises(ValidationError):
        ToolCallRecord.model_validate(payload)


def test_bad_sha256_is_rejected(trace):
    payload = trace.records[0].model_dump()
    for bad in ("abc", "G" * 64, "A" * 64):
        payload["raw_response_sha256"] = bad
        with pytest.raises(ValidationError):
            ToolCallRecord.model_validate(payload)


def test_unknown_field_on_record_is_rejected(trace):
    payload = trace.records[0].model_dump()
    payload["raw_response"] = {"leak": True}
    with pytest.raises(ValidationError):
        ToolCallRecord.model_validate(payload)


def test_find(trace):
    assert trace.find("tc-ioc") is trace.records[1]
    assert trace.find("tc-nope") is None


def test_hash_raw_response_is_canonical():
    a = hash_raw_response({"b": [1, 2], "a": {"y": None, "x": "é"}})
    b = hash_raw_response({"a": {"x": "é", "y": None}, "b": [1, 2]})
    assert a == b
    assert len(a) == 64
    assert a == hash_raw_response({"b": [1, 2], "a": {"y": None, "x": "é"}})
    assert hash_raw_response({"b": [2, 1]}) != hash_raw_response({"b": [1, 2]})
