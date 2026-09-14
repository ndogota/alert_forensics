import json

import pytest
from pydantic import ValidationError

from alert_forensics.contracts import (
    Alert,
    AlertSeverity,
    AlertStatus,
    IpEvidence,
    UnknownEvidence,
    UserEvidence,
)
from conftest import ALERT_PAYLOAD, MINIMAL_ALERT_PAYLOAD


def test_parses_graph_shape(alert):
    assert alert.severity is AlertSeverity.medium
    assert alert.status is AlertStatus.new
    assert alert.created_date_time.tzinfo is not None
    assert alert.mitre_techniques == ["T1078", "T1078.004"]
    user, ip, unknown = alert.evidence
    assert isinstance(user, UserEvidence)
    assert user.user_account is not None
    assert user.user_account.user_principal_name == "jdoe@contoso.com"
    assert isinstance(ip, IpEvidence)
    assert ip.ip_address == "203.0.113.7"
    assert isinstance(unknown, UnknownEvidence)


def test_serialises_by_alias_and_keeps_extras(alert):
    data = json.loads(alert.model_dump_json())
    assert data["createdDateTime"].startswith("2026-09-14T09:58:11.5")
    assert data["mitreTechniques"] == ["T1078", "T1078.004"]
    assert data["someFutureField"] == {"nested": [1, 2, 3]}
    assert data["evidence"][0]["@odata.type"] == "#microsoft.graph.security.userEvidence"
    assert data["evidence"][0]["userAccount"]["userPrincipalName"] == "jdoe@contoso.com"
    assert data["evidence"][2]["@odata.type"] == "#microsoft.graph.security.registryValueEvidence"
    assert data["evidence"][2]["registryKey"] == "HKLM\\Software\\Example"
    assert "created_date_time" not in data


def test_alert_round_trips(alert):
    assert Alert.model_validate_json(alert.model_dump_json()) == alert


def test_rejects_malformed_mitre_ids():
    for bad in ("T12345", "T107", "1078", "T1078.1", "t1078"):
        with pytest.raises(ValidationError):
            Alert.model_validate({**ALERT_PAYLOAD, "mitreTechniques": [bad]})


def test_evidence_without_type_is_rejected():
    with pytest.raises(ValidationError):
        Alert.model_validate({**ALERT_PAYLOAD, "evidence": [{"ipAddress": "1.1.1.1"}]})


def test_evidence_instances_are_accepted_directly(alert):
    rebuilt = Alert(
        id="x",
        title="y",
        created_date_time=alert.created_date_time,
        evidence=list(alert.evidence),
    )
    assert [type(e) for e in rebuilt.evidence] == [UserEvidence, IpEvidence, UnknownEvidence]


def test_populate_by_field_name():
    a = Alert(id="1", title="t", created_date_time="2026-01-01T00:00:00Z")
    assert a.severity is AlertSeverity.unknown
    assert a.evidence == []


def test_to_wire_emits_only_what_the_source_provided():
    parsed = Alert.model_validate(MINIMAL_ALERT_PAYLOAD)
    wire = parsed.to_wire()
    assert wire.keys() == MINIMAL_ALERT_PAYLOAD.keys()
    assert wire["evidence"][0].keys() == MINIMAL_ALERT_PAYLOAD["evidence"][0].keys()
    assert "severity" not in wire
    assert "roles" not in wire["evidence"][0]
    # And it is still a complete, parseable alert.
    assert Alert.model_validate(wire) == parsed
    # The full fixture likewise comes back with exactly its own keys.
    full = Alert.model_validate(ALERT_PAYLOAD).to_wire()
    assert full.keys() == ALERT_PAYLOAD.keys()
    assert full["evidence"][0].keys() == ALERT_PAYLOAD["evidence"][0].keys()
    assert full["evidence"][0]["userAccount"].keys() == (
        ALERT_PAYLOAD["evidence"][0]["userAccount"].keys()
    )
