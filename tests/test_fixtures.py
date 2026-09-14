import pytest

from alert_forensics.contracts import ToolOutcome
from alert_forensics.tools import (
    ANALYST_ROLE,
    DEFINITIONS,
    TOOL_NAMES,
    FixtureAdapter,
    FixtureSet,
    InMemoryRawStore,
    Principal,
    ToolRunner,
    UpstreamError,
    fixture_adapters,
)
from conftest import FIXTURE_TOOLS_DIR, T0

HAPPY_ARGUMENTS = {
    "search_events": {"query": "SigninLogs | where UserPrincipalName == 'jdoe@contoso.com'"},
    "search_siem": {"search": "search index=auth user=jdoe | stats count by src action"},
    "get_identity": {"identity": "jdoe"},
    "get_asset": {"asset": "srv-prd-app01.contoso.com"},
    "lookup_ioc": {"indicator": "203.0.113.7"},
    "get_related_alerts": {"user_principal_name": "jdoe@contoso.com"},
    "get_process_tree": {"device_name": "WS-FIN-0042.contoso.com", "process_id": 4412},
    "search_runbook": {"query": "atypical travel from a corporate gateway"},
    "get_attack_technique": {"technique_id": "T1110.003"},
}


@pytest.fixture(scope="module")
def fixture_set() -> FixtureSet:
    return FixtureSet.load(FIXTURE_TOOLS_DIR)


@pytest.fixture
def runner(fixture_set):
    return ToolRunner(
        adapters=fixture_adapters(fixture_set),
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id="inv-fx",
        clock=lambda: T0,
    )


def test_the_fixture_set_covers_all_nine_tools(fixture_set):
    assert sorted(fixture_set.tools) == sorted(TOOL_NAMES)
    adapters = fixture_adapters(fixture_set)
    assert sorted(a.definition.name for a in adapters) == sorted(TOOL_NAMES)
    assert all(isinstance(a, FixtureAdapter) for a in adapters)


@pytest.mark.parametrize("name", TOOL_NAMES)
def test_each_tool_answers_through_its_fixture_adapter(name, runner):
    record = runner.invoke(
        tool_call_id=f"tc-{name}", step=0, tool_name=name, arguments=HAPPY_ARGUMENTS[name]
    )
    assert record.outcome is ToolOutcome.ok, record.redacted_response
    assert record.source_system is DEFINITIONS[name].source_system
    assert record.required_scope == DEFINITIONS[name].required_scope


def test_exact_contains_and_regex_matchers(fixture_set):
    adapter = FixtureAdapter(DEFINITIONS["search_events"], fixture_set.for_tool("search_events"))
    kql = "DeviceEvents | where ActionType == 'AntivirusDetection'"
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query=kql))
    assert raw["results"][0]["ActionType"] == "AntivirusDetection"
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query="SigninLogs | take 5"))
    assert len(raw["results"]) == 2
    asset = FixtureAdapter(DEFINITIONS["get_asset"], fixture_set.for_tool("get_asset"))
    for spelling in ("SRV-PRD-APP01", "srv-prd-app01.contoso.com"):
        raw = asset.fetch(DEFINITIONS["get_asset"].request_model(asset=spelling))
        assert raw["results"][0]["nt_host"] == "SRV-PRD-APP01"


def test_the_first_matching_stub_wins_in_file_order(fixture_set):
    adapter = FixtureAdapter(DEFINITIONS["search_events"], fixture_set.for_tool("search_events"))
    both = "SigninLogs | join DeviceEvents | where ActionType == 'x'"
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query=both))
    assert raw["results"][0]["AccountUpn"] == "jdoe@contoso.com"


def test_default_answers_when_no_stub_matches(fixture_set):
    adapter = FixtureAdapter(DEFINITIONS["get_identity"], fixture_set.for_tool("get_identity"))
    raw = adapter.fetch(DEFINITIONS["get_identity"].request_model(identity="nobody"))
    assert raw["results"] == []


def test_no_stub_and_no_default_is_a_no_fixture_error(fixture_set, runner):
    adapter = FixtureAdapter(DEFINITIONS["search_siem"], fixture_set.for_tool("search_siem"))
    with pytest.raises(UpstreamError) as info:
        adapter.fetch(DEFINITIONS["search_siem"].request_model(search="index=web"))
    assert info.value.kind == "no_fixture"
    record = runner.invoke(
        tool_call_id="tc-miss", step=0, tool_name="search_siem", arguments={"search": "index=web"}
    )
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "no_fixture"
    assert "index=web" in record.redacted_response["detail"]


def test_a_stub_can_script_an_upstream_error(runner):
    record = runner.invoke(
        tool_call_id="tc-broken",
        step=0,
        tool_name="lookup_ioc",
        arguments={"indicator": "broken.example"},
    )
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response == {
        "error": "upstream_error",
        "tool": "lookup_ioc",
        "detail": "VirusTotal returned HTTP 503",
    }
    record = runner.invoke(
        tool_call_id="tc-nf",
        step=0,
        tool_name="get_attack_technique",
        arguments={"technique_id": "T9999"},
    )
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "not_found"


def test_not_found_ioc_is_a_successful_reading(runner):
    record = runner.invoke(
        tool_call_id="tc-nf",
        step=0,
        tool_name="lookup_ioc",
        arguments={"indicator": "never-seen.example"},
    )
    assert record.outcome is ToolOutcome.ok
    assert record.redacted_response["known"] is False


def test_fixture_files_are_validated_on_load(tmp_path):
    (tmp_path / "lookup_ioc.json").write_text('{"tool": "search_siem", "stubs": []}')
    with pytest.raises(ValueError, match="lookup_ioc"):
        FixtureSet.load(tmp_path)
    (tmp_path / "lookup_ioc.json").write_text('{"tool": "lookup_ioc", "stubs": [{"match": {}}]}')
    with pytest.raises(ValueError, match="response"):
        FixtureSet.load(tmp_path)
    (tmp_path / "nonsense.json").write_text('{"tool": "nonsense", "stubs": []}')
    (tmp_path / "lookup_ioc.json").write_text('{"tool": "lookup_ioc", "stubs": []}')
    with pytest.raises(ValueError, match="nonsense"):
        FixtureSet.load(tmp_path)


def test_both_redaction_layers_apply_end_to_end(runner):
    # Layer one, the projection: the identity view carries no name, phone or coordinates.
    identity = runner.invoke(
        tool_call_id="tc-id", step=0, tool_name="get_identity", arguments={"identity": "jdoe"}
    )
    text = identity.model_dump_json()
    for leaked in ("Jane", "+33 6", "48.8566"):
        assert leaked not in text
    assert identity.redacted_response["email"] == "jdoe@contoso.com"
    # Layer one again, the allowlist: AdditionalFields never reaches the view, and the
    # model is told a column was dropped, not which.
    events = runner.invoke(
        tool_call_id="tc-ev",
        step=1,
        tool_name="search_events",
        arguments={"query": "DeviceEvents | where ActionType == 'AntivirusDetection'"},
    )
    assert events.outcome is ToolOutcome.ok
    assert "eyJhbGciOi" not in events.model_dump_json()
    assert "AdditionalFields" not in events.model_dump_json()
    assert set(events.redacted_response["rows"][0]) == {"Timestamp", "ActionType"}
    assert events.redacted_response["dropped_columns"] == 1
    # Layer two, the generic pass: a password inside a command line is caught although
    # the projection passes the command line through, because it must.
    tree = runner.invoke(
        tool_call_id="tc-tree",
        step=1,
        tool_name="get_process_tree",
        arguments={"device_name": "ws-fin-0042.contoso.com", "process_id": 4412},
    )
    assert tree.outcome is ToolOutcome.ok
    assert "Hunter2!" not in tree.model_dump_json()
    child = tree.redacted_response["lineage"][4]
    assert child["command_line"] == (
        "RemoteSupport.ClientSetup.exe /silent /password=[REDACTED:secret] /relay=relay.example.net"
    )
    # And the raw, by ref, still holds the secret: it is out of context, not destroyed.
    raw = runner.store.get(tree.raw_response_ref, expected_sha256=tree.raw_response_sha256)
    assert "Hunter2!" in raw["results"][2]["ProcessCommandLine"]
