"""Committed recordings under runs/ are real model runs whose raw store verifies."""

from pathlib import Path

import pytest

from alert_forensics.artifact import RunArtifact
from alert_forensics.cli import SCRIPTED_MODEL_ID, main
from alert_forensics.tools import DirectoryRawStore

RECORDINGS = sorted(Path("runs").glob("*/run.json"))


@pytest.mark.parametrize("path", RECORDINGS, ids=[p.parent.name for p in RECORDINGS])
def test_a_recording_is_a_real_run_and_replays(path, capsys):
    artifact = RunArtifact.model_validate_json(path.read_text())
    assert not artifact.model.startswith(SCRIPTED_MODEL_ID.split(":")[0] + ":"), (
        "a recording of the scripted client is a fake demo; record a real model run"
    )
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
