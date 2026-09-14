"""GroundTruth is a contract: one file per scenario, checked against its alert."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from alert_forensics.contracts import Verdict
from alert_forensics.evaluation import (
    GroundTruth,
    GroundTruthError,
    load_scenario,
    load_scenarios,
    scenario_name,
)
from conftest import ALERT_PAYLOAD

TRUTH = {
    "scenario": "atypical_travel",
    "alert_id": ALERT_PAYLOAD["id"],
    "verdict": "false_positive",
    "escalate": False,
    "required_findings": [
        {"name": "paris", "tools": ["search_events"], "tokens": ["203.0.113.7", "Paris"]},
        {"name": "sase", "tools": ["lookup_ioc", "search_runbook"], "tokens": ["SASE"]},
    ],
    "missing_context": [{"name": "vpn_log", "tokens": [["VPN", "SASE"], "log"]}],
}


@pytest.fixture
def examples(tmp_path):
    (tmp_path / "atypical_travel.alert.json").write_text(json.dumps(ALERT_PAYLOAD))
    (tmp_path / "atypical_travel.truth.json").write_text(json.dumps(TRUTH))
    return tmp_path


def test_a_truth_file_loads_beside_its_alert(examples):
    scenario = load_scenario(examples / "atypical_travel.alert.json")
    assert scenario.name == "atypical_travel"
    assert scenario.alert.id == ALERT_PAYLOAD["id"]
    assert scenario.truth.verdict is Verdict.false_positive
    assert scenario.truth.escalate is False
    assert [f.name for f in scenario.truth.required_findings] == ["paris", "sase"]
    assert scenario.truth.required_findings[1].tools == ["lookup_ioc", "search_runbook"]
    assert scenario.truth.missing_context[0].tokens == [["VPN", "SASE"], "log"]


def test_the_scenario_name_is_the_shared_stem():
    assert scenario_name(Path("examples/atypical_travel.alert.json")) == "atypical_travel"
    assert scenario_name(Path("x/y.truth.json")) == "y"
    with pytest.raises(GroundTruthError):
        scenario_name(Path("examples/atypical_travel.json"))


def test_load_scenarios_finds_every_pair_and_narrows_by_name(examples):
    payload = deepcopy(ALERT_PAYLOAD)
    payload["id"] = "other-1"
    (examples / "other.alert.json").write_text(json.dumps(payload))
    (examples / "other.truth.json").write_text(
        json.dumps({**TRUTH, "scenario": "other", "alert_id": "other-1"})
    )
    assert [s.name for s in load_scenarios(examples)] == ["atypical_travel", "other"]
    assert [s.name for s in load_scenarios(examples, only="other")] == ["other"]
    with pytest.raises(GroundTruthError, match="no scenario named"):
        load_scenarios(examples, only="nope")
    with pytest.raises(GroundTruthError, match="no scenario"):
        load_scenarios(examples / "empty")


def test_a_missing_truth_file_is_refused_not_defaulted(examples):
    (examples / "atypical_travel.truth.json").unlink()
    with pytest.raises(GroundTruthError, match="truth"):
        load_scenario(examples / "atypical_travel.alert.json")


def test_a_truth_whose_stem_disagrees_is_refused(examples):
    (examples / "atypical_travel.truth.json").write_text(
        json.dumps({**TRUTH, "scenario": "something_else"})
    )
    with pytest.raises(GroundTruthError, match="something_else"):
        load_scenario(examples / "atypical_travel.alert.json")


def test_a_truth_beside_the_wrong_alert_is_refused(examples):
    (examples / "atypical_travel.truth.json").write_text(
        json.dumps({**TRUTH, "alert_id": "another-alert"})
    )
    with pytest.raises(GroundTruthError, match="another-alert"):
        load_scenario(examples / "atypical_travel.alert.json")


def test_a_finding_names_a_registered_evidence_tool():
    with pytest.raises(ValidationError, match="not a tool"):
        GroundTruth.model_validate(
            {
                **TRUTH,
                "required_findings": [
                    {"name": "x", "tools": ["search_everything"], "tokens": ["a"]}
                ],
            }
        )
    # The write action reads no system; its record is never evidence.
    with pytest.raises(ValidationError, match="never evidence"):
        GroundTruth.model_validate(
            {
                **TRUTH,
                "required_findings": [
                    {"name": "x", "tools": ["propose_alert_disposition"], "tokens": ["a"]}
                ],
            }
        )


def test_names_are_unique_and_tokens_are_never_empty():
    with pytest.raises(ValidationError, match="duplicate"):
        GroundTruth.model_validate(
            {
                **TRUTH,
                "required_findings": [
                    {"name": "same", "tools": ["search_events"], "tokens": ["a"]},
                    {"name": "same", "tools": ["search_events"], "tokens": ["b"]},
                ],
            }
        )
    with pytest.raises(ValidationError):
        GroundTruth.model_validate(
            {
                **TRUTH,
                "required_findings": [{"name": "x", "tools": ["search_events"], "tokens": []}],
            }
        )
    with pytest.raises(ValidationError):
        GroundTruth.model_validate(
            {
                **TRUTH,
                "required_findings": [{"name": "x", "tools": ["search_events"], "tokens": [[]]}],
            }
        )
    with pytest.raises(ValidationError):
        GroundTruth.model_validate({**TRUTH, "missing_context": [{"name": "x", "tokens": [" "]}]})


def test_the_committed_scenario_one_truth_matches_the_spec_table():
    scenario = load_scenario(Path("examples/atypical_travel.alert.json"))
    assert scenario.truth.verdict is Verdict.false_positive
    assert scenario.truth.escalate is False
    assert len(scenario.truth.required_findings) == 3
    assert len(scenario.truth.missing_context) == 2


def test_a_token_that_holds_no_word_is_refused():
    """A token of bare punctuation can never match under the whole-word rule."""
    for tokens in (["..."], ["a", "- -"], [["(", ")"]], [["gateway", "'"]]):
        with pytest.raises(ValidationError, match="no word"):
            GroundTruth.model_validate(
                {
                    **TRUTH,
                    "required_findings": [
                        {"name": "x", "tools": ["search_events"], "tokens": tokens}
                    ],
                }
            )
        with pytest.raises(ValidationError, match="no word"):
            GroundTruth.model_validate(
                {**TRUTH, "missing_context": [{"name": "x", "tokens": tokens}]}
            )
