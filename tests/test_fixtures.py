import json
from pathlib import Path

import pytest

from alert_forensics.artifact import RunArtifact
from alert_forensics.contracts import Alert, ToolOutcome
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
from conftest import ALERT_PAYLOAD, FIXTURE_TOOLS_DIR, T0

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


def bound_runner(fixture_set, labels, investigation_id="inv-fx"):
    return ToolRunner(
        adapters=fixture_adapters(fixture_set, labels),
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id=investigation_id,
        clock=lambda: T0,
    )


@pytest.fixture
def runner(fixture_set):
    """Every label in view: these tests read what the stubs hold, not who may see them."""
    return ToolRunner(
        adapters=fixture_adapters(fixture_set, fixture_set.labels),
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id="inv-fx",
        clock=lambda: T0,
    )


READ_TOOL_NAMES = [n for n in TOOL_NAMES if n != "propose_alert_disposition"]


def test_the_fixture_set_covers_the_nine_read_tools(fixture_set):
    assert sorted(fixture_set.tools) == sorted(READ_TOOL_NAMES)
    adapters = fixture_adapters(fixture_set, fixture_set.labels)
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
    adapter = FixtureAdapter(
        DEFINITIONS["search_events"], fixture_set.for_tool("search_events"), fixture_set.labels
    )
    kql = (
        "DeviceEvents | where DeviceName == 'srv-prd-app01.contoso.com' "
        "| where ActionType == 'PowerShellCommand'"
    )
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query=kql))
    assert raw["results"][0]["ActionType"] == "PowerShellCommand"
    kql = "SigninLogs | where AccountUpn == 'jdoe@contoso.com' | take 5"
    raw = adapter.fetch(DEFINITIONS["search_events"].request_model(query=kql))
    assert len(raw["results"]) == 2
    asset = FixtureAdapter(
        DEFINITIONS["get_asset"], fixture_set.for_tool("get_asset"), {"encoded_powershell"}
    )
    for spelling in ("SRV-PRD-APP01", "srv-prd-app01.contoso.com", "10.20.30.40"):
        raw = asset.fetch(DEFINITIONS["get_asset"].request_model(asset=spelling))
        assert raw["results"][0]["nt_host"] == "SRV-PRD-APP01"


def test_the_first_matching_stub_wins_in_file_order(fixture_set):
    adapter = FixtureAdapter(
        DEFINITIONS["search_events"], fixture_set.for_tool("search_events"), fixture_set.labels
    )
    both = (
        "SigninLogs | where AccountUpn == 'jdoe@contoso.com' "
        "| join DeviceEvents | where DeviceName == 'srv-prd-app01.contoso.com'"
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
    adapter = FixtureAdapter(
        DEFINITIONS["search_siem"], fixture_set.for_tool("search_siem"), fixture_set.labels
    )
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
    # model is told a column was dropped, not which. On scenario 4's DeviceEvents rows
    # that column carries the decoded PowerShell commands, where a script's embedded
    # secrets would sit; the model gets the encoded command line and nothing decoded.
    events = runner.invoke(
        tool_call_id="tc-ev",
        step=1,
        tool_name="search_events",
        arguments={
            "query": "DeviceEvents | where DeviceName =~ 'srv-prd-app01.contoso.com' "
            "| where ActionType == 'PowerShellCommand'"
        },
        turn_siblings=[],
    )
    assert events.outcome is ToolOutcome.ok
    text = events.model_dump_json()
    assert "Restart-WebAppPool" not in text and "Set-ItemProperty" not in text
    assert "AdditionalFields" not in text
    assert "AdditionalFields" not in events.redacted_response["columns"]
    assert "-EncodedCommand" in text
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
        DEFINITIONS["search_runbook"],
        FixtureSet.load(tmp_path).for_tool("search_runbook"),
        {"test"},
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


def test_scenario_2_stubs_answer_nothing_about_another_account(fixture_set, runner):
    """The audit stubs are the account's; the aggregate is keyed on the failure and the
    aggregate, and a query that names a known account gets that account's rows. Inbox
    rules as a subject are scenario 3's since it arrived, so the two assertions that
    name them hold under scenario 2's own binding, which is the weaker claim."""
    assert gap(runner, "search_events", query="CloudAppEvents | where AccountUpn == 'jdoe'")
    spray = bound_runner(fixture_set, {"password_spray"}, "inv-spray-gaps")
    assert gap(spray, "search_events", query="CloudAppEvents | where ActionType has 'InboxRule'")
    assert gap(spray, "search_siem", search="index=o365 user=jdoe New-InboxRule")
    assert gap(runner, "search_siem", search="index=auth user=mmartin | stats count by src")
    assert gap(
        runner, "search_runbook", query="LSASS read blocked, is the account on the exercise list"
    )
    assert gap(runner, "lookup_ioc", indicator="192.0.2.99")
    # jdoe's failures, aggregated, are still jdoe's rows: scenario 1's stub comes first.
    query = (
        "SigninLogs | where AccountUpn == 'jdoe@contoso.com' | where ErrorCode != 0 "
        "| summarize count() by IPAddress"
    )
    assert ok(runner, "search_events", query=query)["rows"][0]["AccountUpn"] == "jdoe@contoso.com"


# --- a stub is offered only to the run of the scenario it serves -----------------------

AGGREGATES = {
    "search_events": [
        "SigninLogs | where ResultType != 0 | summarize dcount(UserPrincipalName), "
        "dcount(IPAddress) by bin(TimeGenerated, 1h)",
        "AADSignInEventsBeta | where ErrorCode != 0 | summarize count() by Country",
    ],
    "search_siem": ["index=auth action=failure | stats dc(user) by src_country"],
}
"""None names rbennett; each was answered with the spray row from any scenario's run."""


def test_the_manifest_binds_a_run_by_the_alerts_id(fixture_set):
    assert fixture_set.scenarios == {
        "atypical_travel": ALERT_PAYLOAD["id"],
        "password_spray": "da637551302218456123_-1188736045",
        "forwarding_rule": "da637551318890123456_-1188736301",
        "encoded_powershell": "da637551341122334455_-1188736402",
    }
    assert fixture_set.in_view(Alert.model_validate(ALERT_PAYLOAD)) == {"shared", "atypical_travel"}
    unknown = Alert.model_validate({**ALERT_PAYLOAD, "id": "nobody-knows-this-alert"})
    assert fixture_set.in_view(unknown) == {"shared"}
    assert fixture_set.labels == {
        "shared",
        "test",
        "atypical_travel",
        "password_spray",
        "forwarding_rule",
        "encoded_powershell",
    }


def test_an_aggregate_stub_answers_only_the_run_of_its_own_scenario(fixture_set):
    spray = bound_runner(fixture_set, {"password_spray"}, "inv-spray")
    travel = bound_runner(fixture_set, {"atypical_travel"}, "inv-travel")
    for tool, queries in AGGREGATES.items():
        argument = "query" if tool == "search_events" else "search"
        for query in queries:
            view = ok(spray, tool, **{argument: query})
            assert view["row_count"] == 1, (tool, query)
            assert gap(travel, tool, **{argument: query}), (tool, query)


def test_shared_stubs_are_always_offered_and_test_stubs_only_when_named(fixture_set):
    travel = bound_runner(fixture_set, {"atypical_travel"}, "inv-travel")
    assert ok(travel, "lookup_ioc", indicator="never-seen.example")["known"] is False
    assert ok(travel, "lookup_ioc", indicator="203.0.113.7")["known"] is True
    assert gap(travel, "lookup_ioc", indicator="192.0.2.44")
    assert gap(travel, "get_asset", asset="srv-prd-app01.contoso.com")
    assert gap(travel, "get_process_tree", device_name="ws-fin-0042.contoso.com", process_id=4412)
    nothing = bound_runner(fixture_set, set(), "inv-none")
    assert ok(nothing, "lookup_ioc", indicator="never-seen.example")["known"] is False
    assert gap(nothing, "lookup_ioc", indicator="203.0.113.7")
    assert gap(nothing, "get_identity", identity="jdoe")
    tests = bound_runner(fixture_set, {"test"}, "inv-test")
    assert gap(tests, "get_asset", asset="srv-prd-app01.contoso.com")
    tree = ok(tests, "get_process_tree", device_name="ws-fin-0042.contoso.com", process_id=4412)
    assert tree["found"] is True
    server = bound_runner(fixture_set, {"encoded_powershell"}, "inv-server")
    assert ok(server, "get_asset", asset="srv-prd-app01.contoso.com")["found"] is True
    assert gap(server, "get_process_tree", device_name="ws-fin-0042.contoso.com", process_id=4412)


def test_a_withheld_stub_is_not_named_in_the_no_fixture_error(fixture_set):
    """The model must not learn that the harness held an answer it withheld."""
    travel = bound_runner(fixture_set, {"atypical_travel"}, "inv-travel")
    record = travel.invoke(
        tool_call_id="tc-withheld",
        step=0,
        tool_name="get_identity",
        arguments={"identity": "rbennett"},
        turn_siblings=[],
    )
    assert record.outcome is ToolOutcome.error
    assert record.redacted_response["error"] == "no_fixture"
    text = json.dumps(record.redacted_response)
    for hidden in ("password_spray", "atypical_travel", "withheld", "shared"):
        assert hidden not in text


def test_a_label_the_manifest_does_not_name_refuses_to_load(tmp_path):
    stub = '{"scenario": "%s", "match": {"indicator": "x"}, "response": {"data": {}}}'
    path = tmp_path / "lookup_ioc.json"
    path.write_text('{"tool": "lookup_ioc", "stubs": [%s]}' % (stub % "nowhere"))
    with pytest.raises(ValueError, match="nowhere"):
        FixtureSet.load(tmp_path)
    (tmp_path / "scenarios.json").write_text('{"nowhere": "alert-x"}')
    loaded = FixtureSet.load(tmp_path)
    assert loaded.scenarios == {"nowhere": "alert-x"}
    assert loaded.labels == {"shared", "test", "nowhere"}
    (tmp_path / "scenarios.json").unlink()
    for label in ("shared", "test"):
        path.write_text('{"tool": "lookup_ioc", "stubs": [%s]}' % (stub % label))
        assert FixtureSet.load(tmp_path).scenarios == {}
    (tmp_path / "scenarios.json").write_text('["not", "a", "manifest"]')
    with pytest.raises(ValueError, match=r"scenarios\.json"):
        FixtureSet.load(tmp_path)


# --- scenario 3, forwarding rule -----------------------------------------------------

AP_USERS = ("amorel", "tkowalski", "lferreira")
ATTACKER = "2001:db8:7a3c:1200::1f"
DESTINATION = "ap.remittance@contoso-invoices.example"


def test_scenario_3_stubs_answer_the_requests_a_model_plausibly_makes(runner):
    # The three users' sign-ins, whichever table and whichever user the model names:
    # one session each from the same address, unmanaged device, MFA reported satisfied.
    tables = ("SigninLogs", "AADSignInEventsBeta", "IdentityLogonEvents")
    for table, user in zip(tables, AP_USERS, strict=True):
        view = ok(
            runner, "search_events", query=f"{table} | where AccountUpn =~ '{user}@contoso.com'"
        )
        assert view["row_count"] == 3, (table, user)
        assert {r["IPAddress"] for r in view["rows"]} == {ATTACKER}
        assert {r["AccountUpn"] for r in view["rows"]} == {f"{u}@contoso.com" for u in AP_USERS}
        assert {r["AuthenticationRequirement"] for r in view["rows"]} == {
            "multiFactorAuthentication"
        }
        assert {r["IsManaged"] for r in view["rows"]} == {False}
        assert "Latitude" not in view["columns"] and view["dropped_columns"] == 2
    # The rules: by user, by destination, or as a tenant-wide listing of inbox rules.
    for query in (
        "CloudAppEvents | where AccountUpn == 'amorel@contoso.com' "
        "| where ActionType == 'New-InboxRule'",
        "OfficeActivity | where UserId has 'lferreira'",
        f"CloudAppEvents | where ActivityObjects has '{DESTINATION}'",
        "CloudAppEvents | where ActionType in ('New-InboxRule', 'Set-InboxRule', 'Set-Mailbox')",
        "AuditLogs | where OperationName has 'InboxRule'",
    ):
        view = ok(runner, "search_events", query=query)
        assert view["row_count"] == 3, query
        assert {r["ActionType"] for r in view["rows"]} == {"New-InboxRule"}
        assert {r["IPAddress"] for r in view["rows"]} == {ATTACKER}
        assert "RawEventData" not in view["columns"] and view["dropped_columns"] == 1
    text = json.dumps(view)
    assert text.count(DESTINATION) == 3
    assert "invoice;IBAN;SWIFT;payment;remittance" in text
    # The same through the SIEM.
    view = ok(runner, "search_siem", search="index=azuread user=amorel | table _time src action")
    assert [r["action"] for r in view["rows"]] == ["success", "success", "success"]
    assert {r["src"] for r in view["rows"]} == {ATTACKER}
    for search in (
        "index=o365 New-InboxRule | table user src object_attrs",
        'index=o365 user="tkowalski@contoso.com" InboxRule',
        f'index=exchange "{DESTINATION}"',
    ):
        view = ok(runner, "search_siem", search=search)
        assert [r["action"] for r in view["rows"]] == ["New-InboxRule"] * 3, search
        assert {r["src"] for r in view["rows"]} == {ATTACKER}
    assert {r["recipient"] for r in view["rows"]} == {DESTINATION}
    # Entities, every spelling the alert carries.
    for user in AP_USERS:
        for spelling in (user, f"{user}@contoso.com", user.upper()):
            identity = ok(runner, "get_identity", identity=spelling)
            assert identity["found"] is True, spelling
            assert (
                identity["business_unit"] == "Accounts Payable" and identity["priority"] == "high"
            )
        related = ok(runner, "get_related_alerts", user_principal_name=f"{user}@contoso.com")
        assert related["count"] == 1 and "sign-in" in related["alerts"][0]["title"].lower()
    assert ok(runner, "get_related_alerts", incident_id="63")["count"] == 3
    reading = ok(runner, "lookup_ioc", indicator=ATTACKER)
    assert reading["known"] is True and reading["indicator_type"] == "ip_address"
    assert reading["engines"]["malicious"] > 0
    reading = ok(runner, "lookup_ioc", indicator="contoso-invoices.example")
    assert reading["known"] is True and reading["indicator_type"] == "domain"
    assert reading["context"]["created_at"].startswith("2026-09-05")
    # The runbook, on the alert type, the destination, or the adversary-in-the-middle
    # entry's subject.
    for query in (
        "Suspicious inbox forwarding rule to an external address",
        "email forwarding rule to an external address, business email compromise",
        "invoice fraud playbook payments desk",
        "AiTM session token replay with MFA satisfied",
        "contoso-invoices.example",
    ):
        assert ok(runner, "search_runbook", query=query)["count"] >= 1, query
    text = json.dumps(ok(runner, "search_runbook", query="inbox forwarding"))
    assert "message trace" in text and "payments desk" in text and "beneficiary" in text


def test_scenario_3_stubs_answer_nothing_about_another_account_and_hold_their_gaps(runner):
    """The sign-in stub is the three users'. What no stub carries is carried by nothing:
    the message trace and the phishing click are the expected missing context."""
    assert gap(
        runner, "search_events", query="SigninLogs | where AccountUpn == 'mmartin@contoso.com'"
    )
    assert gap(runner, "search_siem", search="index=azuread user=mmartin")
    assert gap(
        runner,
        "search_events",
        query=f"EmailEvents | where RecipientEmailAddress == '{DESTINATION}'",
    )
    assert gap(
        runner, "search_events", query="UrlClickEvents | where AccountUpn == 'amorel@contoso.com'"
    )
    assert gap(
        runner,
        "search_siem",
        search=f'index=msexchange recipient="{DESTINATION}" | table sender subject',
    )
    assert gap(runner, "lookup_ioc", indicator="2001:db8:7a3c:1200::2f")
    assert gap(runner, "get_related_alerts", user_principal_name="mmartin@contoso.com")
    assert gap(
        runner, "search_runbook", query="6.2 GB upload to personal cloud storage by a leaver"
    )


# --- scenario 4, encoded PowerShell --------------------------------------------------

SERVER = "srv-prd-app01.contoso.com"
AGENT_SHA256 = "b41c7e2f9a0d3c6e8f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70"
POWERSHELL_SHA256 = "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c"


def test_scenario_4_stubs_answer_the_requests_a_model_plausibly_makes(runner):
    for spelling in ("srv-prd-app01", SERVER, "SRV-PRD-APP01", "10.20.30.40"):
        asset = ok(runner, "get_asset", asset=spelling)
        assert asset["found"] is True and asset["priority"] == "critical", spelling
        assert "pci" in asset["categories"]
    # The lineage around the alert's process, and around its parent.
    tree = ok(runner, "get_process_tree", device_name=SERVER, process_id=5216)
    assert [n["relation"] for n in tree["lineage"]] == ["grandparent", "parent", "self"]
    grandparent, parent, me = tree["lineage"]
    assert grandparent["file_name"] == "services.exe"
    assert parent["file_name"] == "cfgagent.exe" and parent["account"] == "SYSTEM"
    assert parent["folder_path"] == "C:\\Program Files\\Contoso\\ConfigAgent"
    assert me["file_name"] == "powershell.exe" and "-EncodedCommand" in me["command_line"]
    assert me["account"] == "SYSTEM" and me["sha256"] == POWERSHELL_SHA256
    tree = ok(runner, "get_process_tree", device_name="SRV-PRD-APP01", process_id=1840)
    assert [n["relation"] for n in tree["lineage"]] == [
        "grandparent",
        "parent",
        "self",
        "child",
        "child",
    ]
    assert {n["file_name"] for n in tree["lineage"][3:]} == {"powershell.exe"}
    # Process events on the device: today's run and the previous window's.
    for query in (
        f"DeviceProcessEvents | where DeviceName =~ '{SERVER}' "
        "| where FileName =~ 'powershell.exe'",
        "DeviceProcessEvents | where DeviceName startswith 'srv-prd-app01' "
        "| where ProcessCommandLine has '-enc'",
    ):
        view = ok(runner, "search_events", query=query)
        assert view["row_count"] == 2, query
        assert {r["InitiatingProcessFileName"] for r in view["rows"]} == {"cfgagent.exe"}
        assert {r["AccountName"] for r in view["rows"]} == {"SYSTEM"}
        assert all("-EncodedCommand" in r["ProcessCommandLine"] for r in view["rows"])
        assert view["dropped_columns"] == 0
    view = ok(runner, "search_events", query=f"DeviceEvents | where DeviceName == '{SERVER}'")
    assert view["row_count"] == 3 and {r["ActionType"] for r in view["rows"]} == {
        "PowerShellCommand"
    }
    assert {r["InitiatingProcessParentFileName"] for r in view["rows"]} == {"cfgagent.exe"}
    # The SIEM: process events, and the change calendar that declares the window.
    for search in (
        "index=wineventlog host=srv-prd-app01 EventCode=4688 process_name=powershell.exe",
        f'index=endpoint dest="{SERVER}" parent_process_name=cfgagent.exe | table _time process',
    ):
        view = ok(runner, "search_siem", search=search)
        assert [r["parent_process_name"] for r in view["rows"]] == ["cfgagent.exe"] * 2, search
        assert {r["user"] for r in view["rows"]} == {"SYSTEM"}
        assert all("-EncodedCommand" in r["process"] for r in view["rows"])
    for search in (
        '| inputlookup change_calendar where host="srv-prd-app01"',
        f"index=change_mgmt dest={SERVER} maintenance window",
        "index=itsm CHG0042117",
    ):
        view = ok(runner, "search_siem", search=search)
        assert view["row_count"] == 1, search
        row = view["rows"][0]
        assert row["object"] == "CHG0042117" and row["object_category"] == "change"
        assert row["status"] == "approved" and "2026-09-14T02:00" in row["object_attrs"]
    # The owner, the prior alert on the device, and the two hashes.
    owner = ok(runner, "get_identity", identity="platform-ops@contoso.com")
    assert owner["found"] is True and owner["business_unit"] == "Infrastructure"
    for arguments in (
        {"device_name": SERVER},
        {"device_name": "SRV-PRD-APP01"},
        {"incident_id": "66"},
    ):
        related = ok(runner, "get_related_alerts", **arguments)
        assert related["count"] == 1, arguments
        prior = related["alerts"][0]
        assert prior["classification"] == "informationalExpectedActivity"
        assert prior["determination"] == "lineOfBusinessApplication"
        assert prior["created_date_time"].startswith("2026-08-31")
    reading = ok(runner, "lookup_ioc", indicator=AGENT_SHA256)
    assert reading["known"] is False
    reading = ok(runner, "lookup_ioc", indicator=POWERSHELL_SHA256)
    assert reading["known"] is True and reading["context"]["signed"] is True
    assert "Microsoft" in reading["context"]["signers"] and reading["engines"]["malicious"] == 0
    # The runbook: the alert type, the agent, the server, the ticket, the window.
    for query in (
        "Encoded PowerShell command on a production server",
        "cfgagent.exe configuration management agent expected parent",
        "maintenance window srv-prd-app01",
        "CHG0042117",
        "powershell -EncodedCommand as SYSTEM on a production server, is it sanctioned",
    ):
        assert ok(runner, "search_runbook", query=query)["count"] >= 1, query
    text = json.dumps(ok(runner, "search_runbook", query="encoded powershell"))
    assert "triplet" in text and "do not disable" in text and "CHG0042117" in text


def test_scenario_4_stubs_answer_nothing_about_another_device(runner):
    assert gap(runner, "get_asset", asset="srv-prd-app02")
    assert gap(runner, "get_process_tree", device_name="srv-prd-app02.contoso.com", process_id=5216)
    assert gap(
        runner, "search_events", query="DeviceProcessEvents | where DeviceName == 'srv-prd-app02'"
    )
    assert gap(
        runner, "search_events", query="DeviceEvents | where ActionType == 'PowerShellCommand'"
    )
    assert gap(runner, "search_siem", search="index=wineventlog host=srv-prd-app02 powershell")
    assert gap(
        runner, "search_siem", search="| inputlookup change_calendar where host=srv-prd-app02"
    )
    assert gap(runner, "get_related_alerts", device_name="srv-prd-app02.contoso.com")
    assert gap(runner, "lookup_ioc", indicator="0" * 64)


# --- what carries which label -----------------------------------------------------------


def test_the_only_test_stub_left_is_the_workstation_tree_scenario_7_will_claim(fixture_set):
    remaining = [
        (tool, index)
        for tool in sorted(fixture_set.tools)
        for index, stub in enumerate(fixture_set.tools[tool].stubs)
        if stub.scenario == "test"
    ]
    assert remaining == [("get_process_tree", 0)]
    stub = fixture_set.for_tool("get_process_tree").stubs[0]
    assert stub.match["device_name"] == {"$regex": "(?i)^ws-fin-0042"}


def test_stub_counts_per_label_are_what_the_spec_says(fixture_set):
    from collections import Counter

    counts = Counter(
        stub.scenario for fixture in fixture_set.tools.values() for stub in fixture.stubs
    )
    assert counts == {
        "atypical_travel": 6,
        "password_spray": 11,
        "forwarding_rule": 14,
        "encoded_powershell": 11,
        "shared": 5,
        "test": 1,
    }
