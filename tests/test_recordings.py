"""Committed recordings under runs/<scenario>/<recording>/ are real model runs whose raw
store verifies, each named in runs/README.md."""

import re
from pathlib import Path

import pytest

from alert_forensics.artifact import RunArtifact
from alert_forensics.cli import SCRIPTED_MODEL_ID, main
from alert_forensics.tools import DirectoryRawStore

RUNS = Path("runs")
RECORDINGS = sorted(RUNS.glob("*/*/run.json"))


def recording_id(path: Path) -> str:
    return f"{path.parent.parent.name}/{path.parent.name}"


def check_recording(path: Path) -> RunArtifact:
    """The contract under "Using it": a real model run the provider served, with at
    least one model turn, whose raw store verifies. Served is the artifact's own
    ``refused``, the one definition the scorer reads, so a run refused after work is
    refused here too."""
    artifact = RunArtifact.model_validate_json(path.read_text())
    assert not artifact.model.startswith(SCRIPTED_MODEL_ID.split(":")[0] + ":"), (
        "a recording of the scripted client is a fake demo; record a real model run"
    )
    assert not artifact.refused, (
        f"the provider refused this run ({artifact.error and artifact.error.kind}); a "
        "refused run is the quota's, before any turn or after work, and is not a recording"
    )
    assert artifact.trace.usage, "a recording holds at least one model turn"
    store = DirectoryRawStore(path.parent / artifact.raw_store)
    for record in artifact.trace.records:
        store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256)
    return artifact


@pytest.mark.parametrize("path", RECORDINGS, ids=[recording_id(p) for p in RECORDINGS])
def test_a_recording_is_a_real_run_and_replays(path, capsys):
    artifact = check_recording(path)
    assert main(["replay", str(path)]) == 0
    assert artifact.model in capsys.readouterr().out


def test_a_run_refused_after_work_is_not_a_recording(trace, tmp_path):
    """The case: run 2 of scenario 1's first cell, failed_error of kind rate_limit after
    two model turns and two tool calls, which a check reading trace.usage admitted. Built
    here in the same shape, since the results directory is not committed."""
    artifact = RunArtifact.model_validate(
        {
            "investigation_id": trace.investigation_id,
            "outcome": "failed_error",
            "model": "google_genai:gemini-3.5-flash-lite",
            "model_limits": {"timeout_s": 60, "max_retries": 1},
            "output_binding": {
                "strategy": "tool",
                "profile_declared": True,
                "structured_output": False,
            },
            "role": "analyst",
            "adapters": {"search_events": "fixture"},
            "trace": trace.model_copy(update={"records": trace.records[:2]}),
            "report": None,
            "passes": 0,
            "error": {"kind": "rate_limit", "message": "429 RESOURCE_EXHAUSTED"},
            "raw_store": "run.raw",
        }
    )
    assert len(artifact.trace.usage) == 2 and len(artifact.trace.records) == 2
    path = tmp_path / "atypical_travel" / "refused-case" / "run.json"
    path.parent.mkdir(parents=True)
    path.write_text(artifact.model_dump_json(indent=2))
    with pytest.raises(AssertionError, match="refused"):
        check_recording(path)


def test_no_recording_yet_is_stated_not_hidden():
    if RECORDINGS:
        pytest.skip("recordings exist")
    readme = Path("README.md").read_text()
    assert "no recorded run" in readme.lower() or "not yet" in readme.lower()


def test_the_runs_readme_names_every_recording_and_nothing_else():
    """What is there and what the README says are the same list."""
    readme = (RUNS / "README.md").read_text()
    named = set(re.findall(r"`runs/([a-z_]+/[a-z0-9_-]+)/`", readme))
    present = {recording_id(p) for p in RECORDINGS}
    assert named == present, (sorted(named - present), sorted(present - named))


def test_the_committed_recordings_are_the_ones_the_spec_decided():
    """One demonstration run per scenario that has a completed real run, the first such
    run by rule, plus every run the spec cites: the first recording under the defaults,
    the two no-fact runs of scenario 5, the two spray runs that pivoted on the address,
    scenario 7's run that called no tool and the three of its second-campaign cell
    that called none either, and the three gate runs of the priced tiers on scenario
    1, cited for the asset question and the strict binding."""
    assert {recording_id(p) for p in RECORDINGS} == {
        "atypical_travel/defaults-2026-09-14",
        "atypical_travel/campaign-0",
        "atypical_travel/probe-gpt-5-nano",
        "atypical_travel/probe-gpt-5-nano-strict",
        "atypical_travel/probe-sonnet-5",
        "cloud_upload/campaign-0",
        "encoded_powershell/campaign-3",
        "forwarding_rule/campaign-3",
        "kerberoasting/campaign-0",
        "lsass_access/campaign-3",
        "lsass_access/campaign-4",
        "lsass_access/campaign-5",
        "password_spray/campaign-3",
        "password_spray/campaign-5",
        "rmm_block/campaign-0",
        "rmm_block/campaign-02-3",
        "rmm_block/campaign-02-4",
        "rmm_block/campaign-02-5",
    }


SILENT = ["campaign-0", "campaign-02-3", "campaign-02-4", "campaign-02-5"]
"""Scenario 7's recordings, every one a served run in which the model called no tool."""


@pytest.mark.parametrize("recording", SILENT)
def test_the_recording_that_called_no_tool_is_a_served_run_with_no_raw_store(recording):
    """Scenario 7's real runs: two model turns, no request, no raw response, so no
    directory beside it; the trace refers to nothing and git keeps no empty directory."""
    path = RUNS / "rmm_block" / recording / "run.json"
    artifact = RunArtifact.model_validate_json(path.read_text())
    assert artifact.trace.records == [] and len(artifact.trace.usage) == 2
    assert not (path.parent / artifact.raw_store).exists()
