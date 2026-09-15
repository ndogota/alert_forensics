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


@pytest.mark.parametrize("path", RECORDINGS, ids=[recording_id(p) for p in RECORDINGS])
def test_a_recording_is_a_real_run_and_replays(path, capsys):
    artifact = RunArtifact.model_validate_json(path.read_text())
    assert not artifact.model.startswith(SCRIPTED_MODEL_ID.split(":")[0] + ":"), (
        "a recording of the scripted client is a fake demo; record a real model run"
    )
    # A run the provider refused before any turn holds nothing to replay.
    assert artifact.trace.records, "a recording holds at least one tool call"
    store = DirectoryRawStore(path.parent / artifact.raw_store)
    for record in artifact.trace.records:
        store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256)
    assert main(["replay", str(path)]) == 0
    assert artifact.model in capsys.readouterr().out


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
    """One demonstration run per recorded scenario, the first completed of the campaign
    by rule, plus every run the spec cites: the first recording under the defaults, the
    two no-fact runs of scenario 5, and the two spray runs that pivoted on the address."""
    assert {recording_id(p) for p in RECORDINGS} == {
        "atypical_travel/defaults-2026-09-14",
        "atypical_travel/campaign-0",
        "encoded_powershell/campaign-3",
        "forwarding_rule/campaign-3",
        "kerberoasting/campaign-0",
        "lsass_access/campaign-3",
        "lsass_access/campaign-4",
        "lsass_access/campaign-5",
        "password_spray/campaign-3",
        "password_spray/campaign-5",
    }
