from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import JsonValue

from alert_forensics.contracts import (
    Alert,
    Assumption,
    InvestigationTrace,
    MissingContext,
    ModelUsageRecord,
    ObservedFact,
    SourceSystem,
    ToolCallRecord,
    ToolOutcome,
    TriageResult,
    Verdict,
    hash_raw_response,
)
from alert_forensics.contracts.trace import InputTokenDetails

T0 = datetime(2026, 9, 14, 10, 0, 0, 123456, tzinfo=UTC)
PARIS = timezone(timedelta(hours=2))

ALERT_PAYLOAD = {
    "id": "da637551227677560813_-961444813",
    "title": "Atypical travel",
    "description": "Sign-in from Paris then Amsterdam within 40 minutes.",
    "severity": "medium",
    "status": "new",
    "category": "InitialAccess",
    "createdDateTime": "2026-09-14T09:58:11.5Z",
    "lastUpdateDateTime": "2026-09-14T09:59:00Z",
    "detectionSource": "azureAdIdentityProtection",
    "serviceSource": "azureAdIdentityProtection",
    "providerAlertId": "6f1b3d2e",
    "tenantId": "b3c1c5fc-1f6e-4a2c-9b6a-2c0d8c0f4a11",
    "incidentId": "41",
    "mitreTechniques": ["T1078", "T1078.004"],
    "someFutureField": {"nested": [1, 2, 3]},
    "evidence": [
        {
            "@odata.type": "#microsoft.graph.security.userEvidence",
            "createdDateTime": "2026-09-14T09:58:11.5Z",
            "verdict": "suspicious",
            "roles": ["compromised"],
            "userAccount": {
                "accountName": "jdoe",
                "userPrincipalName": "jdoe@contoso.com",
                "azureAdUserId": "0f6a...",
            },
        },
        {
            "@odata.type": "#microsoft.graph.security.ipEvidence",
            "ipAddress": "203.0.113.7",
            "countryLetterCode": "NL",
        },
        {
            "@odata.type": "#microsoft.graph.security.registryValueEvidence",
            "registryKey": "HKLM\\Software\\Example",
            "registryValueName": "Run",
            "nested": {"a": [1, {"b": None}]},
        },
    ],
}


@pytest.fixture
def alert() -> Alert:
    return Alert.model_validate(ALERT_PAYLOAD)


def make_record(
    tool_call_id: str,
    tool_name: str,
    source_system: SourceSystem,
    *,
    step: int = 0,
    outcome: ToolOutcome = ToolOutcome.ok,
    started_at: datetime = T0,
    raw: JsonValue | None = None,
    caller: str = "analyst",
    required_scope: str | None = None,
) -> ToolCallRecord:
    raw_value = raw if raw is not None else {"tool": tool_name, "rows": [1, 2.5, "x", None]}
    return ToolCallRecord(
        tool_call_id=tool_call_id,
        step=step,
        tool_name=tool_name,
        source_system=source_system,
        caller=caller,
        required_scope=required_scope or f"{source_system.value}:read",
        arguments={"query": f"from {tool_name}", "limit": 10, "flags": [True, None]},
        started_at=started_at,
        duration_us=1500,
        outcome=outcome,
        redacted_response={"tool": tool_name, "rows": [1, 2.5, "x", None], "user": "[REDACTED]"},
        raw_response_ref=f"artifacts/inv-1/{tool_call_id}.json",
        raw_response_sha256=hash_raw_response(raw_value),
    )


@pytest.fixture
def trace(alert: Alert) -> InvestigationTrace:
    return InvestigationTrace(
        investigation_id="inv-1",
        alert=alert,
        started_at=T0,
        records=[
            make_record("tc-events", "search_events", SourceSystem.defender, step=0),
            make_record(
                "tc-ioc",
                "lookup_ioc",
                SourceSystem.virustotal,
                step=0,
                started_at=T0.astimezone(PARIS),
            ),
            make_record("tc-identity", "get_identity", SourceSystem.splunk, step=1),
            make_record(
                "tc-siem-denied",
                "search_siem",
                SourceSystem.splunk,
                step=1,
                outcome=ToolOutcome.denied,
                required_scope="siem:raw_search",
                raw={"error": "scope_denied", "required_scope": "siem:raw_search"},
            ),
        ],
        usage=[
            ModelUsageRecord(
                step=0,
                model="anthropic:claude-sonnet-5",
                input_tokens=1200,
                output_tokens=80,
                total_tokens=1280,
                input_token_details=InputTokenDetails(cache_read=1000),
            ),
            ModelUsageRecord(
                step=1,
                model="anthropic:claude-sonnet-5",
                input_tokens=1900,
                output_tokens=120,
                total_tokens=2020,
            ),
        ],
    )


@pytest.fixture
def grounded_result() -> TriageResult:
    return TriageResult(
        verdict=Verdict.false_positive,
        confidence=0.9,
        mitre_techniques=["T1078.004"],
        observed_facts=[
            ObservedFact(
                statement="Both sign-ins originate from the group SASE gateway range.",
                evidence=["tc-events"],
            ),
            ObservedFact(
                statement="The egress IP has no detections on VirusTotal.",
                evidence=["tc-ioc"],
            ),
            ObservedFact(
                statement="The account is a standard user with medium priority.",
                evidence=["tc-identity"],
            ),
        ],
        assumptions=[
            Assumption(
                statement="The user was on the corporate VPN at both times.",
                why_unverified="VPN session logs were not queried.",
            )
        ],
        missing_context=[
            MissingContext(
                what="VPN session log for the user around both sign-ins",
                why_it_matters="Confirms the gateway explanation directly.",
                how_to_obtain="Query the SASE provider audit log.",
            )
        ],
        recommended_action=(
            "Close as false positive; add the gateway range to the travel allowlist."
        ),
        escalate=False,
    )


def with_facts(result: TriageResult, facts: list[ObservedFact]) -> TriageResult:
    return result.model_copy(update={"observed_facts": facts})


MINIMAL_ALERT_PAYLOAD = {
    "id": "min-1",
    "title": "Minimal",
    "createdDateTime": "2026-09-14T09:58:11Z",
    "evidence": [
        {
            "@odata.type": "#microsoft.graph.security.registryValueEvidence",
            "registryKey": "HKLM\\Software\\Example",
        }
    ],
}
