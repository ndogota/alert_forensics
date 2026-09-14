"""Every example alert resolves offline through the default adapter set."""

import json
import shutil
from pathlib import Path

import pytest

from alert_forensics.cli import default_adapters
from alert_forensics.contracts import Alert, ToolOutcome
from alert_forensics.evaluation import fixture_collisions, load_scenarios, stale_labels
from alert_forensics.fixtures import DEFAULT_FIXTURES_DIR
from alert_forensics.tools import ANALYST_ROLE, FixtureSet, InMemoryRawStore, Principal, ToolRunner

EXAMPLES = sorted(Path("examples").glob("*.alert.json"))


def test_there_is_at_least_one_example():
    assert EXAMPLES


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_every_declared_technique_resolves_offline(path):
    alert = Alert.model_validate(json.loads(path.read_text()))
    assert alert.mitre_techniques, f"{path.name} declares no technique; the example should"
    runner = ToolRunner(
        adapters=default_adapters(DEFAULT_FIXTURES_DIR, scripted=True, alert=alert),
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id="inv-examples",
    )
    for n, technique in enumerate(alert.mitre_techniques):
        record = runner.invoke(
            tool_call_id=f"tc-{n}",
            step=0,
            tool_name="get_attack_technique",
            arguments={"technique_id": technique},
            turn_siblings=[],
        )
        assert record.outcome is ToolOutcome.ok, (technique, record.redacted_response)
        assert record.redacted_response["technique_id"] == technique
    assert runner.adapters["get_attack_technique"].kind == "recorded"


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_every_example_has_a_ground_truth_that_loads_beside_it(path):
    from alert_forensics.evaluation import load_scenario

    scenario = load_scenario(path)
    assert scenario.truth.alert_id == scenario.alert.id
    assert scenario.truth.required_findings, f"{path.name}: a scenario requires findings"


# --- no stub answers another scenario's question, over whatever scenarios exist ---------

SCENARIOS = load_scenarios(Path("examples"))


def test_no_shipped_stub_answers_another_scenarios_question():
    found = fixture_collisions(FixtureSet.load(DEFAULT_FIXTURES_DIR), SCENARIOS)
    assert found == [], [f"{c.tool} stub {c.stub} ({c.label}) answers {c.scenario}" for c in found]


def test_every_stub_label_names_a_present_scenario_shared_or_test():
    assert stale_labels(FixtureSet.load(DEFAULT_FIXTURES_DIR), SCENARIOS) == []


def stub_file(tmp_path, tool, label, match, response):
    (tmp_path / f"{tool}.json").write_text(
        json.dumps(
            {"tool": tool, "stubs": [{"scenario": label, "match": match, "response": response}]}
        )
    )


def manifest(tmp_path):
    (tmp_path / "scenarios.json").write_text(json.dumps({s.name: s.alert.id for s in SCENARIOS}))


def test_a_colliding_stub_is_named_with_the_scenario_it_would_answer(tmp_path):
    manifest(tmp_path)
    # An operator matcher that the alert's title satisfies.
    stub_file(tmp_path, "search_runbook", "test", {"query": {"$regex": "(?i)travel"}}, {"hits": []})
    # An exact value that is one of the alert's entities.
    stub_file(tmp_path, "get_identity", "test", {"identity": "jdoe"}, {"results": []})
    found = fixture_collisions(FixtureSet.load(tmp_path), SCENARIOS)
    assert [(c.tool, c.stub, c.label, c.scenario) for c in found] == [
        ("get_identity", 0, "test", "atypical_travel"),
        ("search_runbook", 0, "test", "atypical_travel"),
    ]
    # The alert's own scenario is exempt, and so is a shared exact stub.
    travel = {"query": {"$regex": "(?i)travel"}}
    stub_file(tmp_path, "search_runbook", "atypical_travel", travel, {"hits": []})
    stub_file(tmp_path, "get_identity", "shared", {"identity": "jdoe"}, {"results": []})
    assert fixture_collisions(FixtureSet.load(tmp_path), SCENARIOS) == []
    # A stub about nothing the alert names does not collide.
    other = {"query": {"$contains": "kerberoast"}}
    stub_file(tmp_path, "search_runbook", "test", other, {"hits": []})
    assert fixture_collisions(FixtureSet.load(tmp_path), SCENARIOS) == []


def test_a_manifest_entry_naming_no_present_scenario_is_stale(tmp_path):
    """A label outside the manifest refuses to load; a manifest entry outside the
    scenarios present is what can go stale."""
    (tmp_path / "scenarios.json").write_text(json.dumps({"nowhere": "alert-x"}))
    stub_file(tmp_path, "search_runbook", "nowhere", {"query": {"$contains": "x"}}, {"hits": []})
    stale = stale_labels(FixtureSet.load(tmp_path), SCENARIOS)
    assert len(stale) == 1 and "nowhere" in stale[0]


def test_the_shipped_manifest_names_every_scenario_under_examples_by_its_alert_id():
    manifest = FixtureSet.load(DEFAULT_FIXTURES_DIR).scenarios
    assert manifest == {s.name: s.alert.id for s in SCENARIOS}


# --- the probe's limit, and the questions real models actually asked ------------------

from alert_forensics.evaluation import RecordedRequest, recorded_requests  # noqa: E402

RUNS = Path("runs")
RECORDINGS = recorded_requests(RUNS, SCENARIOS)

INFRASTRUCTURE_WORDS = {"query": {"$regex": "(?i)egress|gateway|proxy|vpn"}}
"""The exact shape of the defect that created the labelling rule."""


def test_the_alert_probe_alone_misses_a_stub_keyed_on_infrastructure_words(tmp_path):
    """No alert carries those words; the collision came from a model's question."""
    stub_file(tmp_path, "search_runbook", "test", INFRASTRUCTURE_WORDS, {"hits": []})
    assert fixture_collisions(FixtureSet.load(tmp_path), SCENARIOS) == []


def test_the_recording_probe_catches_it(tmp_path):
    manifest(tmp_path)
    """The committed scenario 1 recording asked the runbook about "VPN SASE corporate
    egress proxy Amsterdam Paris". Put to a stub that does not serve scenario 1, that
    question is a collision, named with the recording it came from."""
    stub_file(tmp_path, "search_runbook", "test", INFRASTRUCTURE_WORDS, {"hits": []})
    found = fixture_collisions(FixtureSet.load(tmp_path), SCENARIOS, requests=RECORDINGS)
    assert [(c.tool, c.stub, c.label, c.scenario, c.probe) for c in found] == [
        ("search_runbook", 0, "test", "atypical_travel", "recording")
    ]
    # The recording's own scenario is exempt, as it is for the alert probe.
    stub_file(tmp_path, "search_runbook", "atypical_travel", INFRASTRUCTURE_WORDS, {"hits": []})
    assert fixture_collisions(FixtureSet.load(tmp_path), SCENARIOS, requests=RECORDINGS) == []


def test_a_collision_from_the_alert_is_labelled_as_such(tmp_path):
    stub_file(tmp_path, "get_identity", "test", {"identity": "jdoe"}, {"results": []})
    found = fixture_collisions(FixtureSet.load(tmp_path), SCENARIOS, requests=RECORDINGS)
    assert [(c.tool, c.scenario, c.probe) for c in found] == [
        ("get_identity", "atypical_travel", "alert")
    ]


def test_recorded_requests_are_every_request_of_every_committed_recording():
    assert RECORDINGS, "the corpus is one run today; it must not be empty"
    assert {r.scenario for r in RECORDINGS} == {p.parent.name for p in RUNS.glob("*/run.json")}
    travel = [r for r in RECORDINGS if r.scenario == "atypical_travel"]
    assert [r.tool for r in travel] == [
        "search_events",
        "lookup_ioc",
        "get_identity",
        "search_runbook",
        "get_attack_technique",
        "propose_alert_disposition",
    ]
    runbook = next(r for r in travel if r.tool == "search_runbook")
    assert runbook.arguments == {"query": "VPN SASE corporate egress proxy Amsterdam Paris"}
    assert isinstance(runbook, RecordedRequest)


def test_a_recording_that_names_no_scenario_present_fails_the_check(tmp_path):
    runs = tmp_path / "runs"
    shutil.copytree(RUNS / "atypical_travel", runs / "nowhere")
    with pytest.raises(ValueError, match="nowhere"):
        recorded_requests(runs, SCENARIOS)


def test_a_recording_beside_the_wrong_scenario_fails_the_check(tmp_path):
    runs = tmp_path / "runs"
    shutil.copytree(RUNS / "atypical_travel", runs / "password_spray")
    with pytest.raises(ValueError, match="password_spray"):
        recorded_requests(runs, SCENARIOS)


def test_no_shipped_stub_answers_a_question_a_recording_asked():
    found = fixture_collisions(
        FixtureSet.load(DEFAULT_FIXTURES_DIR), SCENARIOS, requests=RECORDINGS
    )
    assert found == [], [f"{c.tool} stub {c.stub} ({c.label}) answers {c.scenario}" for c in found]


# --- a tool is listed on a finding only when its reading carries the finding's words ----

from alert_forensics.evaluation import contains_tokens  # noqa: E402
from alert_forensics.tools import DEFINITIONS  # noqa: E402
from alert_forensics.tools.redaction import redact  # noqa: E402


def readings(fixture_set: FixtureSet, scenario: str, tool: str) -> list[str]:
    """What the model sees from each of the scenario's stubs for the tool: the raw
    response projected through the definition and redacted, as text."""
    definition = DEFINITIONS[tool]
    out = []
    for stub in fixture_set.for_tool(tool).stubs:
        if stub.scenario != scenario or stub.error is not None:
            continue
        response = definition.response_model.model_validate(stub.response)
        request = None
        if tool == "get_process_tree":
            # The tree pivots on a request; the stub's first row is the pivot.
            first = response.results[0]
            request = definition.request_model(
                device_name=first["DeviceName"], process_id=first["ProcessId"]
            )
        view = definition.projector(response, request)
        out.append(json.dumps(redact(view.model_dump(mode="json")), ensure_ascii=False))
    return out


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_every_listed_tool_reading_carries_the_findings_words(scenario):
    fixture_set = FixtureSet.load(DEFAULT_FIXTURES_DIR)
    for finding in scenario.truth.required_findings:
        for tool in finding.tools:
            views = readings(fixture_set, scenario.name, tool)
            assert views, f"{scenario.name}: {finding.name} lists {tool}, which has no stub"
            missed = [contains_tokens(view, finding.tokens) for view in views]
            assert any(not m for m in missed), (
                f"{scenario.name}: {finding.name} lists {tool}, whose readings lack {missed}"
            )


# --- scenario 2 ---------------------------------------------------------------------------

LABELS = {
    "atypical_travel": ("false_positive", False),
    "password_spray": ("true_positive", True),
    "forwarding_rule": ("true_positive", True),
    "encoded_powershell": ("benign_true_positive", False),
}


def test_the_shipped_scenarios_are_labelled_as_the_table_says():
    assert {s.name: (s.truth.verdict.value, s.truth.escalate) for s in SCENARIOS} == LABELS


@pytest.mark.parametrize("technique", ["T1556.006", "T1564.008"])
def test_the_follow_on_techniques_scenario_2_resolves_are_in_the_excerpt(technique):
    """Not on the alert; a model that names them offline must resolve them."""
    alert = next(s for s in SCENARIOS if s.name == "password_spray").alert
    runner = ToolRunner(
        adapters=default_adapters(DEFAULT_FIXTURES_DIR, scripted=True, alert=alert),
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id="inv-follow-on",
    )
    record = runner.invoke(
        tool_call_id="tc-0",
        step=0,
        tool_name="get_attack_technique",
        arguments={"technique_id": technique},
        turn_siblings=[],
    )
    assert record.outcome is ToolOutcome.ok, record.redacted_response
    assert record.redacted_response["technique_id"] == technique
    assert runner.adapters["get_attack_technique"].kind == "recorded"
