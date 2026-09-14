import json
from pathlib import Path

import pytest

from alert_forensics.artifact import RunArtifact
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


READ_TOOL_NAMES = [n for n in TOOL_NAMES if n != "propose_alert_disposition"]


def test_the_fixture_set_covers_the_nine_read_tools(fixture_set):
    assert sorted(fixture_set.tools) == sorted(READ_TOOL_NAMES)
    adapters = fixture_adapters(fixture_set)
    assert sorted(a.definition.name for a in adapters) == sorted(READ_TOOL_NAMES)
    assert all(isinstance(a, FixtureAdapter) for a in adapters)
    assert all(a.kind == "fixture" for a in adapters)


@pytest.mark.parametrize("name", READ_TOOL_NAMES)
def test_each_tool_answers_through_its_fixture_adapter(name, runner):
    record = runner.invoke(
        tool_call_id=f"tc-{name}",
        step=0,
        tool_name=name,
        arguments=HAPPY_ARGUMENTS[name],
        turn_siblings=[],
    )
    assert record.outcome is ToolOutcome.ok, record.redacted_response
    assert record.source_system is DEFINITIONS[name].source_system
    assert record.required_scope == DEFINITIONS[name].required_scope


def test_exact_contains_and_regex_matchers(fixture_set):
    adapter = FixtureAdapter(DEFINITIONS["search_events"], fixture_set.for_tool("search_events"))
    kql = "DeviceEvents | where ActionType == 'AntivirusDetection'"
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query=kql))
    assert raw["results"][0]["ActionType"] == "AntivirusDetection"
    kql = "SigninLogs | where AccountUpn == 'jdoe@contoso.com' | take 5"
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query=kql))
    assert len(raw["results"]) == 2
    asset = FixtureAdapter(DEFINITIONS["get_asset"], fixture_set.for_tool("get_asset"))
    for spelling in ("SRV-PRD-APP01", "srv-prd-app01.contoso.com"):
        raw = asset.fetch(DEFINITIONS["get_asset"].request_model(asset=spelling))
        assert raw["results"][0]["nt_host"] == "SRV-PRD-APP01"


def test_the_first_matching_stub_wins_in_file_order(fixture_set):
    adapter = FixtureAdapter(DEFINITIONS["search_events"], fixture_set.for_tool("search_events"))
    both = (
        "SigninLogs | where AccountUpn == 'jdoe@contoso.com' "
        "| join DeviceEvents | where ActionType == 'AntivirusDetection'"
    )
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query=both))
    assert raw["results"][0]["AccountUpn"] == "jdoe@contoso.com"


UNANTICIPATED_ARGUMENTS = {
    "search_events": {"query": "EmailEvents | where SenderFromAddress has 'invoice'"},
    "search_siem": {"search": "index=web"},
    "get_identity": {"identity": "nobody"},
    "get_asset": {"asset": "nobody"},
    "lookup_ioc": {"indicator": "198.51.100.200"},
    "get_related_alerts": {"user_principal_name": "nobody@contoso.com"},
    "get_process_tree": {"device_name": "nobody", "process_id": 1},
    "search_runbook": {"query": "printer toner"},
    "get_attack_technique": {"technique_id": "T0000"},
}


@pytest.mark.parametrize("name", READ_TOOL_NAMES)
def test_a_request_no_stub_answers_is_a_no_fixture_error_on_every_shipped_fixture(name, runner):
    """No shipped fixture answers a request it did not anticipate with an empty result.
    Five of them did, and the model read the emptiness as a reading."""
    record = runner.invoke(
        tool_call_id=f"tc-gap-{name}",
        step=0,
        tool_name=name,
        arguments=UNANTICIPATED_ARGUMENTS[name],
        turn_siblings=[],
    )
    assert record.outcome is ToolOutcome.error, record.redacted_response
    assert record.redacted_response["error"] == "no_fixture"


def test_a_fixture_default_is_refused_on_load(tmp_path):
    (tmp_path / "search_runbook.json").write_text(
        '{"tool": "search_runbook", "stubs": [], "default": {"response": {"hits": []}}}'
    )
    with pytest.raises(ValueError, match="default"):
        FixtureSet.load(tmp_path)


def test_a_stub_that_constrains_no_argument_is_refused_on_load(tmp_path):
    catch_alls = (
        "{}",
        '{"query": {"$any": true}}',
        '{"query": {"$any": true}, "top_k": {"$any": true}}',
    )
    for match in catch_alls:
        (tmp_path / "search_runbook.json").write_text(
            '{"tool": "search_runbook", "stubs": '
            f'[{{"scenario": "test", "match": {match}, "response": {{"hits": []}}}}]}}'
        )
        with pytest.raises(ValueError, match="constrain"):
            FixtureSet.load(tmp_path)
    (tmp_path / "search_runbook.json").unlink()
    # $any beside a real constraint is fine: any process on this device.
    (tmp_path / "get_process_tree.json").write_text(
        '{"tool": "get_process_tree", "stubs": [{"scenario": "test", '
        '"match": {"device_name": "ws-1", "process_id": {"$any": true}}, '
        '"response": {"schema": [], "results": []}}]}'
    )
    assert "get_process_tree" in FixtureSet.load(tmp_path).tools


def test_scenario_1_stubs_answer_the_requests_a_model_plausibly_makes(runner):
    """The committed recording asked these and was handed empties by the defaults."""
    runbook = runner.invoke(
        tool_call_id="tc-rb",
        step=0,
        tool_name="search_runbook",
        arguments={"query": "VPN SASE corporate egress proxy Amsterdam Paris"},
        turn_siblings=[],
    )
    assert runbook.outcome is ToolOutcome.ok
    assert runbook.redacted_response["count"] >= 1
    assert "SASE gateways egress" in json.dumps(runbook.redacted_response)
    for n, spelling in enumerate(("jdoe@contoso.com", "JDOE")):
        identity = runner.invoke(
            tool_call_id=f"tc-id-{n}",
            step=0,
            tool_name="get_identity",
            arguments={"identity": spelling},
            turn_siblings=[],
        )
        assert identity.outcome is ToolOutcome.ok
        assert identity.redacted_response["found"] is True, spelling
    for n, table in enumerate(("SigninLogs", "AADSignInEventsBeta", "IdentityLogonEvents")):
        events = runner.invoke(
            tool_call_id=f"tc-ev-{n}",
            step=0,
            tool_name="search_events",
            arguments={"query": f"{table} | where AccountUpn == 'jdoe@contoso.com'"},
            turn_siblings=[],
        )
        assert events.outcome is ToolOutcome.ok
        assert events.redacted_response["row_count"] == 2, table


def test_no_stub_is_a_no_fixture_error(fixture_set, runner):
    adapter = FixtureAdapter(DEFINITIONS["search_siem"], fixture_set.for_tool("search_siem"))
    with pytest.raises(UpstreamError) as info:
        adapter.fetch(DEFINITIONS["search_siem"].request_model(search="index=web"))
    assert info.value.kind == "no_fixture"
    record = runner.invoke(
        tool_call_id="tc-miss",
        step=0,
        tool_name="search_siem",
        arguments={"search": "index=web"},
        turn_siblings=[],
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
        turn_siblings=[],
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
        turn_siblings=[],
    )
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "not_found"


def test_not_found_ioc_is_a_successful_reading(runner):
    record = runner.invoke(
        tool_call_id="tc-nf",
        step=0,
        tool_name="lookup_ioc",
        arguments={"indicator": "never-seen.example"},
        turn_siblings=[],
    )
    assert record.outcome is ToolOutcome.ok
    assert record.redacted_response["known"] is False


def test_fixture_files_are_validated_on_load(tmp_path):
    (tmp_path / "lookup_ioc.json").write_text('{"tool": "search_siem", "stubs": []}')
    with pytest.raises(ValueError, match="lookup_ioc"):
        FixtureSet.load(tmp_path)
    (tmp_path / "lookup_ioc.json").write_text(
        '{"tool": "lookup_ioc", "stubs": [{"scenario": "test", "match": {"indicator": "x"}}]}'
    )
    with pytest.raises(ValueError, match="response"):
        FixtureSet.load(tmp_path)
    (tmp_path / "nonsense.json").write_text('{"tool": "nonsense", "stubs": []}')
    (tmp_path / "lookup_ioc.json").write_text('{"tool": "lookup_ioc", "stubs": []}')
    with pytest.raises(ValueError, match="nonsense"):
        FixtureSet.load(tmp_path)


def test_both_redaction_layers_apply_end_to_end(runner):
    # Layer one, the projection: the identity view carries no name, phone or coordinates.
    identity = runner.invoke(
        tool_call_id="tc-id",
        step=0,
        tool_name="get_identity",
        arguments={"identity": "jdoe"},
        turn_siblings=[],
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
        turn_siblings=[],
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
        turn_siblings=[],
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


# --- a free-text stub answers only questions about the entities it holds ---------------


def gap(runner, name, **arguments):
    record = runner.invoke(
        tool_call_id=f"tc-{name}-{abs(hash(json.dumps(arguments, sort_keys=True)))}",
        step=0,
        tool_name=name,
        arguments=arguments,
        turn_siblings=[],
    )
    return record.outcome is ToolOutcome.error and record.redacted_response["error"] == "no_fixture"


def test_a_sign_in_query_about_another_account_is_a_no_fixture_error(runner):
    """The table is a shape and a shape matches every user. jdoe's rows are jdoe's."""
    other = 'SigninLogs | where UserPrincipalName == "mmartin@contoso.com" | where ResultType != 0'
    assert gap(runner, "search_events", query=other)
    assert gap(runner, "search_events", query="AADSignInEventsBeta | take 10")
    assert gap(runner, "search_events", query="DeviceEvents | where ActionType == 'ProcessCreated'")
    assert gap(runner, "search_siem", search="search index=auth user=mmartin | stats count by src")
    assert gap(runner, "search_siem", search="search index=auth | stats count by user")


def test_a_runbook_query_on_another_subject_is_a_no_fixture_error(runner):
    """Infrastructure words are every scenario's words; the entry is about one subject."""
    for query in (
        "RMM tool blocked by EDR, is the relay our IT provider egress",
        "kerberoasting 180 SPNs in 90 seconds credentialed vulnerability scanner",
        "corporate egress proxy gateway VPN",
        "DNS tunnelling over TXT records from a build agent",
    ):
        assert gap(runner, "search_runbook", query=query), query


def test_the_recordings_own_requests_still_hit(runner):
    """Replayed from the artifact itself, so the check cannot drift from the recording."""
    artifact = RunArtifact.model_validate_json(Path("runs/atypical_travel/run.json").read_text())
    replayed = {}
    for record in artifact.trace.records:
        if record.tool_name not in ("search_events", "search_runbook", "get_identity"):
            continue
        replayed[record.tool_name] = runner.invoke(
            tool_call_id=f"tc-replay-{record.tool_name}",
            step=0,
            tool_name=record.tool_name,
            arguments=record.arguments,
            turn_siblings=[],
        )
    assert sorted(replayed) == ["get_identity", "search_events", "search_runbook"]
    assert all(r.outcome is ToolOutcome.ok for r in replayed.values())
    assert replayed["search_events"].redacted_response["row_count"] == 2
    assert replayed["get_identity"].redacted_response["found"] is True
    assert replayed["search_runbook"].redacted_response["count"] >= 1
    assert "SASE gateways egress" in json.dumps(replayed["search_runbook"].redacted_response)


def test_all_requires_every_matcher_and_an_all_of_anys_is_unconstrained(tmp_path):
    (tmp_path / "search_runbook.json").write_text(
        '{"tool": "search_runbook", "stubs": [{"scenario": "test", "match": {"query": {"$all": '
        '[{"$regex": "(?i)travel"}, {"$contains": "SASE"}]}}, "response": {"hits": []}}]}'
    )
    adapter = FixtureAdapter(
        DEFINITIONS["search_runbook"], FixtureSet.load(tmp_path).for_tool("search_runbook")
    )
    request = DEFINITIONS["search_runbook"].request_model
    assert adapter.fetch(request(query="atypical travel via SASE")) == {"hits": []}
    for query in ("atypical travel", "the SASE gateway", "nothing"):
        with pytest.raises(UpstreamError) as info:
            adapter.fetch(request(query=query))
        assert info.value.kind == "no_fixture"
    for catch_all in ("[]", '[{"$any": true}]', '[{"$any": true}, {"$any": true}]'):
        (tmp_path / "search_runbook.json").write_text(
            '{"tool": "search_runbook", "stubs": [{"scenario": "test", "match": {"query": {"$all": '
            f'{catch_all}}}}}, "response": {{"hits": []}}}}]}}'
        )
        with pytest.raises(ValueError, match="constrain"):
            FixtureSet.load(tmp_path)


def test_a_stub_names_its_scenario_and_a_shared_stub_is_exact(tmp_path):
    path = tmp_path / "lookup_ioc.json"
    path.write_text(
        '{"tool": "lookup_ioc", "stubs": [{"match": {"indicator": "x"}, "response": {"data": {}}}]}'
    )
    with pytest.raises(ValueError, match="scenario"):
        FixtureSet.load(tmp_path)
    path.write_text(
        '{"tool": "lookup_ioc", "stubs": [{"scenario": "shared", '
        '"match": {"indicator": {"$regex": "^x"}}, "response": {"data": {}}}]}'
    )
    with pytest.raises(ValueError, match="exact"):
        FixtureSet.load(tmp_path)
    path.write_text(
        '{"tool": "lookup_ioc", "stubs": [{"scenario": "shared", '
        '"match": {"indicator": "x"}, "response": {"data": {}}}]}'
    )
    assert FixtureSet.load(tmp_path).for_tool("lookup_ioc").stubs[0].scenario == "shared"


# --- scenario 2, password spray ------------------------------------------------------


def ok(runner, name, **arguments):
    record = runner.invoke(
        tool_call_id=f"tc-{name}-{len(runner.records)}",
        step=0,
        tool_name=name,
        arguments=arguments,
        turn_siblings=[],
    )
    assert record.outcome is ToolOutcome.ok, record.redacted_response
    return record.redacted_response


RBENNETT = "rbennett@contoso.com"


def test_scenario_2_stubs_answer_the_requests_a_model_plausibly_makes(runner):
    # The account's sign-ins, whichever table the model chooses: one failure from a
    # spray source, then the success and the interactive session from 192.0.2.44.
    for table in ("SigninLogs", "AADSignInEventsBeta", "IdentityLogonEvents"):
        view = ok(runner, "search_events", query=f"{table} | where AccountUpn == '{RBENNETT}'")
        assert view["row_count"] == 3, table
        actions = [r["ActionType"] for r in view["rows"]]
        assert actions == ["LogonFailed", "LogonSuccess", "LogonSuccess"]
        assert view["rows"][1]["IPAddress"] == "192.0.2.44"
        assert "Latitude" not in view["columns"] and view["dropped_columns"] == 2
    # The account's audit events: the new method and the inbox rule, from the same address.
    for table in ("CloudAppEvents", "AuditLogs", "IdentityDirectoryEvents"):
        view = ok(runner, "search_events", query=f"{table} | where AccountUpn =~ '{RBENNETT}'")
        actions = [r["ActionType"] for r in view["rows"]]
        assert actions == ["User registered security info", "New-InboxRule"], table
        assert {r["IPAddress"] for r in view["rows"]} == {"192.0.2.44"}
        assert "RawEventData" not in view["columns"] and view["dropped_columns"] == 1
    text = json.dumps(view)
    assert "RSS Feeds" in text and "password;MFA" in text, "the rule's parameters reach the model"
    # The tenant-wide aggregate of failures: three distinct counts in one row, read, not
    # computed.
    for query in (
        "AADSignInEventsBeta | where ErrorCode != 0 "
        "| summarize dcount(AccountUpn), dcount(IPAddress), dcount(Country)",
        "SigninLogs | where ResultType == 50126 | summarize count() by IPAddress, Country",
        "IdentityLogonEvents | where ActionType == 'LogonFailed' "
        "| summarize dcount(AccountUpn) by IPAddress",
    ):
        view = ok(runner, "search_events", query=query)
        assert view["row_count"] == 1, query
        row = view["rows"][0]
        counts = (row["dcount_AccountUpn"], row["dcount_IPAddress"], row["dcount_Country"])
        assert counts == (137, 31, 12)
        assert len(row["make_set_IPAddress"]) == 31 and "192.0.2.44" in row["make_set_IPAddress"]
        assert len(row["make_set_Country"]) == 12
    # The same three readings through the SIEM.
    view = ok(runner, "search_siem", search="search index=auth user=rbennett | table _time src")
    assert [r["action"] for r in view["rows"]] == ["failure", "success", "success"]
    audit = f'index=o365 user="{RBENNETT}" (New-InboxRule OR "security info")'
    view = ok(runner, "search_siem", search=audit)
    assert [r["action"] for r in view["rows"]] == ["User registered security info", "New-InboxRule"]
    stats = "index=auth action=failure | stats dc(user) dc(src) dc(src_country) count"
    row = ok(runner, "search_siem", search=stats)["rows"][0]
    assert (row["dc(user)"], row["dc(src)"], row["dc(src_country)"]) == ("137", "31", "12")
    # Entities, both spellings where the alert carries both.
    for spelling in ("rbennett", RBENNETT, "RBENNETT"):
        assert ok(runner, "get_identity", identity=spelling)["found"] is True, spelling
    assert ok(runner, "get_identity", identity="rbennett")["priority"] == "high"
    related = ok(runner, "get_related_alerts", user_principal_name=RBENNETT)
    assert related["count"] == 1 and "inbox" in related["alerts"][0]["title"].lower()
    for address in ("192.0.2.44", "192.0.2.17"):
        reading = ok(runner, "lookup_ioc", indicator=address)
        assert reading["known"] is True and reading["indicator"] == address
    # The runbook, on the alert type or on the user agent the entry explains.
    for query in ("password spray playbook thresholds", "Password Spraying", "what is BAV2ROPC"):
        assert ok(runner, "search_runbook", query=query)["count"] >= 1, query
    text = json.dumps(ok(runner, "search_runbook", query="password spray"))
    assert "100 or more" in text and "25 or more" in text and "5 or more" in text


def test_scenario_2_stubs_answer_nothing_about_another_account(runner):
    """The audit stubs are the account's; the aggregate is keyed on the failure and the
    aggregate, and a query that names a known account gets that account's rows."""
    assert gap(runner, "search_events", query="CloudAppEvents | where AccountUpn == 'jdoe'")
    assert gap(runner, "search_events", query="CloudAppEvents | where ActionType has 'InboxRule'")
    assert gap(runner, "search_siem", search="index=o365 user=jdoe New-InboxRule")
    assert gap(runner, "search_siem", search="index=auth user=mmartin | stats count by src")
    assert gap(runner, "search_runbook", query="inbox rule forwarding invoices outside the bank")
    assert gap(runner, "lookup_ioc", indicator="192.0.2.99")
    # jdoe's failures, aggregated, are still jdoe's rows: scenario 1's stub comes first.
    query = (
        "SigninLogs | where AccountUpn == 'jdoe@contoso.com' | where ErrorCode != 0 "
        "| summarize count() by IPAddress"
    )
    assert ok(runner, "search_events", query=query)["rows"][0]["AccountUpn"] == "jdoe@contoso.com"
