import json

import pytest
from pydantic import JsonValue

from alert_forensics import validate_grounding
from alert_forensics.contracts import (
    InvestigationTrace,
    ObservedFact,
    SourceSystem,
    ToolOutcome,
    TriageResult,
    Verdict,
    hash_raw_response,
)
from alert_forensics.tools import (
    ANALYST_ROLE,
    DEFINITIONS,
    TIER1_ROLE,
    InMemoryRawStore,
    Principal,
    ToolAdapter,
    ToolRunner,
    UpstreamError,
    redact,
)
from conftest import T0

IOC_RAW: JsonValue = {
    "data": {
        "id": "203.0.113.7",
        "type": "ip_address",
        "attributes": {
            "as_owner": "EXAMPLE-SASE-NET",
            "asn": 64496,
            "country": "NL",
            "last_analysis_date": 1789300000,
            "last_analysis_stats": {
                "harmless": 60,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 34,
                "timeout": 0,
            },
            "last_analysis_results": {"Abusix": {"category": "harmless"}},
            "reputation": 0,
            "tags": ["Bearer abcDEF0123456789abcDEF0123456789"],
            "total_votes": {"harmless": 0, "malicious": 0},
            "whois": "phone: +31 20 000 0000",
        },
    }
}


class ScriptedAdapter(ToolAdapter):
    """Returns whatever it was told to; records the requests it received."""

    def __init__(
        self, name: str, *, raw: JsonValue | None = None, error: UpstreamError | None = None
    ):
        super().__init__(DEFINITIONS[name])
        self.raw = raw
        self.error = error
        self.requests: list[object] = []

    def fetch(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.raw


@pytest.fixture
def store():
    return InMemoryRawStore()


def make_runner(adapters, store, role=ANALYST_ROLE, caller="analyst"):
    return ToolRunner(
        adapters=adapters,
        principal=Principal(name=caller, role=role),
        store=store,
        investigation_id="inv-1",
        clock=lambda: T0,
    )


def test_ok_call_is_journalled_with_raw_out_of_context(store):
    adapter = ScriptedAdapter("lookup_ioc", raw=IOC_RAW)
    runner = make_runner([adapter], store)
    record = runner.invoke(
        tool_call_id="tc-ioc",
        step=2,
        tool_name="lookup_ioc",
        arguments={"indicator": "203.0.113.7"},
    )
    assert record.outcome is ToolOutcome.ok
    assert record.tool_name == "lookup_ioc"
    assert record.source_system is SourceSystem.virustotal
    assert record.caller == "analyst"
    assert record.required_scope == "ioc:lookup"
    assert record.step == 2
    assert record.started_at == T0
    assert record.arguments == {"indicator": "203.0.113.7"}
    assert isinstance(record.duration_us, int)
    # The raw is in the store, by ref and hash; it is not in the record.
    assert record.raw_response_sha256 == hash_raw_response(IOC_RAW)
    assert store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256) == IOC_RAW
    text = record.model_dump_json()
    assert "last_analysis_results" not in text
    assert "+31 20" not in text
    assert "abcDEF0123456789" not in text
    # The redacted response is exactly the redacted projection of the validated raw.
    definition = DEFINITIONS["lookup_ioc"]
    expected = redact(
        definition.project(definition.response_model.model_validate(IOC_RAW)).model_dump(
            mode="json"
        )
    )
    assert record.redacted_response == expected
    assert record.redacted_response["detection_ratio"] == "0/94"
    assert record.redacted_response["tags"] == ["Bearer [REDACTED:token]"]
    assert adapter.requests[0].indicator == "203.0.113.7"
    assert runner.records == [record]


def test_denied_call_never_reaches_the_adapter(store):
    adapter = ScriptedAdapter("search_siem", raw={"sid": "1", "results": []})
    runner = make_runner([adapter], store, role=TIER1_ROLE, caller="t1-oncall")
    record = runner.invoke(
        tool_call_id="tc-siem", step=0, tool_name="search_siem", arguments={"search": "index=auth"}
    )
    assert record.outcome is ToolOutcome.denied
    assert adapter.requests == []
    assert record.caller == "t1-oncall"
    assert record.required_scope == "siem:search"
    assert record.redacted_response["error"] == "scope_denied"
    assert record.redacted_response["role"] == "tier1"
    # The denial is what upstream "returned"; it is stored and hashed like any response.
    assert store.get(record.raw_response_ref) == record.redacted_response
    assert record.raw_response_sha256 == hash_raw_response(record.redacted_response)


def test_invalid_arguments_are_an_error_the_model_can_read(store):
    adapter = ScriptedAdapter("lookup_ioc", raw=IOC_RAW)
    runner = make_runner([adapter], store)
    record = runner.invoke(
        tool_call_id="tc-bad", step=0, tool_name="lookup_ioc", arguments={"ioc": "203.0.113.7"}
    )
    assert record.outcome is ToolOutcome.error
    assert adapter.requests == []
    assert record.redacted_response["error"] == "invalid_arguments"
    assert record.redacted_response["tool"] == "lookup_ioc"
    assert "indicator" in record.redacted_response["detail"]
    assert record.arguments == {"ioc": "203.0.113.7"}


def test_upstream_failure_is_an_error_not_an_exception(store):
    adapter = ScriptedAdapter(
        "lookup_ioc", error=UpstreamError("upstream_error", "VirusTotal returned HTTP 503")
    )
    runner = make_runner([adapter], store)
    record = runner.invoke(
        tool_call_id="tc-503",
        step=0,
        tool_name="lookup_ioc",
        arguments={"indicator": "203.0.113.7"},
    )
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response == {
        "error": "upstream_error",
        "tool": "lookup_ioc",
        "detail": "VirusTotal returned HTTP 503",
    }
    assert store.get(record.raw_response_ref) == record.redacted_response


def test_malformed_response_is_an_error_and_the_raw_is_still_stored(store):
    malformed: JsonValue = {"data": {"id": "203.0.113.7", "attributes": "not-a-dict"}}
    adapter = ScriptedAdapter("lookup_ioc", raw=malformed)
    runner = make_runner([adapter], store)
    record = runner.invoke(
        tool_call_id="tc-mal",
        step=0,
        tool_name="lookup_ioc",
        arguments={"indicator": "203.0.113.7"},
    )
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "malformed_response"
    assert (
        store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256) == malformed
    )
    assert "not-a-dict" not in json.dumps(record.redacted_response)


def test_unknown_tool_is_an_error(store):
    runner = make_runner([], store)
    record = runner.invoke(tool_call_id="tc-x", step=0, tool_name="close_alert", arguments={})
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "unknown_tool"
    assert record.tool_name == "close_alert"
    assert record.source_system is SourceSystem.none
    assert record.required_scope == "none"
    assert "close_alert" in record.redacted_response["detail"]
    # A defined tool with no adapter registered is the same error, filed under its system.
    record = runner.invoke(tool_call_id="tc-y", step=0, tool_name="search_siem", arguments={})
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "unknown_tool"
    assert record.source_system is SourceSystem.splunk
    assert "no adapter" in record.redacted_response["detail"]


def test_a_tool_call_id_is_journalled_once(store):
    runner = make_runner([ScriptedAdapter("lookup_ioc", raw=IOC_RAW)], store)
    runner.invoke(
        tool_call_id="tc-1", step=0, tool_name="lookup_ioc", arguments={"indicator": "1.1.1.1"}
    )
    with pytest.raises(ValueError, match="tc-1"):
        runner.invoke(
            tool_call_id="tc-1", step=1, tool_name="lookup_ioc", arguments={"indicator": "1.1.1.1"}
        )


def test_records_feed_the_trace_and_the_grounding_validator(alert, store):
    runner = make_runner(
        [
            ScriptedAdapter("lookup_ioc", raw=IOC_RAW),
            ScriptedAdapter("search_siem", raw={"sid": "1", "results": []}),
        ],
        store,
        role=TIER1_ROLE,
        caller="t1",
    )
    ok = runner.invoke(
        tool_call_id="tc-ok", step=0, tool_name="lookup_ioc", arguments={"indicator": "203.0.113.7"}
    )
    denied = runner.invoke(
        tool_call_id="tc-denied", step=0, tool_name="search_siem", arguments={"search": "x"}
    )
    trace = InvestigationTrace(
        investigation_id="inv-1", alert=alert, started_at=T0, records=runner.records
    )
    assert InvestigationTrace.model_validate_json(trace.model_dump_json()) == trace
    result = TriageResult(
        verdict=Verdict.false_positive,
        confidence=0.8,
        observed_facts=[
            ObservedFact(statement="No engine flags the egress IP.", evidence=[ok.tool_call_id]),
            ObservedFact(statement="Splunk shows nothing.", evidence=[denied.tool_call_id]),
        ],
        recommended_action="Close.",
        escalate=False,
    )
    report = validate_grounding(result, trace)
    assert [f.grounded for f in report.facts] == [True, False]
    assert report.facts[1].problems[0].kind == "cites_unsuccessful_call"
    assert report.facts[0].source_systems == [SourceSystem.virustotal]


def test_the_runner_journals_one_call_at_a_time(store):
    import threading

    runner = make_runner([ScriptedAdapter("lookup_ioc", raw=IOC_RAW)], store)
    errors: list[Exception] = []

    def call(n: int) -> None:
        try:
            runner.invoke(
                tool_call_id=f"tc-{n % 4}",
                step=0,
                tool_name="lookup_ioc",
                arguments={"indicator": "203.0.113.7"},
            )
        except ValueError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=call, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r.tool_call_id for r in runner.records) == ["tc-0", "tc-1", "tc-2", "tc-3"]
    assert len(errors) == 4 and all("already journalled" in str(e) for e in errors)


def test_every_journalled_record_reaches_the_callback_in_journal_order(store):
    seen = []
    runner = ToolRunner(
        adapters=[ScriptedAdapter("lookup_ioc", raw=IOC_RAW)],
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=store,
        investigation_id="inv-1",
        clock=lambda: T0,
        on_record=seen.append,
    )
    runner.invoke(
        tool_call_id="tc-1", step=0, tool_name="lookup_ioc", arguments={"indicator": "1.2.3.4"}
    )
    runner.invoke(tool_call_id="tc-2", step=1, tool_name="no_such_tool", arguments={})
    assert seen == runner.records
    assert [r.outcome for r in seen] == [ToolOutcome.ok, ToolOutcome.error]


# --- The write action comes after evidence, and alone ------------------------------

IOC_ARGS = {"indicator": "203.0.113.7"}
PROPOSAL_ARGS = {
    "verdict": "false_positive",
    "recommended_action": "Close.",
    "escalate": False,
    "summary": "Gateway.",
}


def _propose(runner, tool_call_id="tc-propose", step=1, siblings=()):
    return runner.invoke(
        tool_call_id=tool_call_id,
        step=step,
        tool_name="propose_alert_disposition",
        arguments=dict(PROPOSAL_ARGS),
        turn_siblings=list(siblings),
    )


def test_a_proposal_before_any_ok_record_is_denied_by_rule(store):
    from alert_forensics.tools.disposition import DispositionAdapter

    runner = make_runner([DispositionAdapter(clock=lambda: T0)], store)
    record = _propose(runner, step=0)
    assert record.outcome is ToolOutcome.denied
    assert record.required_scope == "alerts:write"
    assert record.redacted_response["error"] == "order_denied"
    assert record.redacted_response["rule"] == "needs_evidence"
    assert record.redacted_response["tool"] == "propose_alert_disposition"
    assert record.redacted_response["caller"] == "analyst"
    assert record.redacted_response["role"] == "analyst"
    assert "ok" in record.redacted_response["message"]
    assert store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256)


def test_a_failed_call_is_not_evidence_enough_but_an_ok_call_is(store):
    from alert_forensics.tools.disposition import DispositionAdapter

    failing = ScriptedAdapter("lookup_ioc", error=UpstreamError("upstream_error", "down"))
    runner = make_runner([failing, DispositionAdapter(clock=lambda: T0)], store)
    runner.invoke(
        tool_call_id="tc-1", step=0, tool_name="lookup_ioc", arguments={"indicator": "203.0.113.7"}
    )
    assert _propose(runner, "tc-p1").outcome is ToolOutcome.denied
    runner.adapters["lookup_ioc"] = ScriptedAdapter("lookup_ioc", raw=IOC_RAW)
    runner.invoke(
        tool_call_id="tc-2", step=1, tool_name="lookup_ioc", arguments={"indicator": "203.0.113.7"}
    )
    assert _propose(runner, "tc-p2", step=2).outcome is ToolOutcome.ok


def test_a_proposal_beside_another_call_in_its_turn_is_denied_by_rule(store):
    from alert_forensics.tools.disposition import DispositionAdapter

    runner = make_runner(
        [ScriptedAdapter("lookup_ioc", raw=IOC_RAW), DispositionAdapter(clock=lambda: T0)], store
    )
    runner.invoke(
        tool_call_id="tc-1", step=0, tool_name="lookup_ioc", arguments={"indicator": "203.0.113.7"}
    )
    record = _propose(runner, step=1, siblings=["lookup_ioc", "get_identity"])
    assert record.outcome is ToolOutcome.denied
    assert record.redacted_response["rule"] == "alone_in_turn"
    assert "lookup_ioc" in record.redacted_response["message"]
    # A read-only tool has no ordering rules: siblings are nothing to it.
    sibling = runner.invoke(
        tool_call_id="tc-2",
        step=1,
        tool_name="lookup_ioc",
        arguments=IOC_ARGS,
        turn_siblings=["propose_alert_disposition"],
    )
    assert sibling.outcome is ToolOutcome.ok


def test_scope_is_checked_before_order(store):
    from alert_forensics.tools.disposition import DispositionAdapter

    runner = make_runner([DispositionAdapter(clock=lambda: T0)], store, role=TIER1_ROLE)
    record = _propose(runner, step=0)
    assert record.outcome is ToolOutcome.denied
    assert record.redacted_response["error"] == "scope_denied"
