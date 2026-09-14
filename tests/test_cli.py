import json
import tomllib
from pathlib import Path

import pytest

from alert_forensics.artifact import RunArtifact
from alert_forensics.cli import main
from alert_forensics.contracts import DispositionDecision, RunOutcome, ToolOutcome, Verdict
from alert_forensics.tools import DirectoryRawStore
from conftest import ALERT_PAYLOAD


@pytest.fixture
def alert_file(tmp_path):
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(ALERT_PAYLOAD))
    return path


def test_the_console_script_is_declared():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())
    assert pyproject["project"]["scripts"]["alert-forensics"] == "alert_forensics.cli:main"


def test_triage_scripted_writes_the_artifact_and_the_raw_store_beside_it(alert_file, tmp_path):
    out = tmp_path / "run.json"
    assert main(["triage", str(alert_file), "--scripted", "--accept", "-o", str(out)]) == 0
    artifact = RunArtifact.model_validate_json(out.read_text())
    assert artifact.outcome is RunOutcome.completed
    assert artifact.model == "scripted:demo"
    assert artifact.role == "analyst"
    assert artifact.report is not None and artifact.report.is_grounded
    assert artifact.report.result.verdict is Verdict.inconclusive
    assert artifact.report.result.missing_context
    assert artifact.report.total_facts >= 3
    assert artifact.raw_store == "run.raw"
    store = DirectoryRawStore(tmp_path / "run.raw")
    for record in artifact.trace.records:
        assert store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256)
    assert artifact.decisions[0].decision is DispositionDecision.accepted
    propose = artifact.trace.find(artifact.decisions[0].tool_call_id)
    assert propose is not None and propose.outcome is ToolOutcome.ok
    assert artifact.trace.alert.id == ALERT_PAYLOAD["id"]
    assert set(artifact.adapters.values()) == {"fixture", "local"}
    # A demo run cites only calls that succeeded; the trace may hold errors too.
    assert all(f.grounded for f in artifact.report.facts)
    assert any(r.outcome is ToolOutcome.error for r in artifact.trace.records)


def test_show_prints_the_result_readably(alert_file, tmp_path, capsys):
    out = tmp_path / "run.json"
    main(["triage", str(alert_file), "--scripted", "--accept", "-o", str(out)])
    capsys.readouterr()
    assert main(["show", str(out)]) == 0
    text = capsys.readouterr().out
    assert "completed" in text
    assert "inconclusive" in text
    assert "Observed facts" in text and "Missing context" in text and "Assumptions" in text
    assert "accepted" in text
    artifact = RunArtifact.model_validate_json(out.read_text())
    for fact in artifact.report.facts:
        assert fact.evidence_ids[0] in text
    assert "search_events" in text


def test_reject_records_the_reason_and_runs_no_proposal(alert_file, tmp_path):
    out = tmp_path / "run.json"
    code = main(["triage", str(alert_file), "--scripted", "--reject", "Not today", "-o", str(out)])
    assert code == 0
    artifact = RunArtifact.model_validate_json(out.read_text())
    assert artifact.decisions[0].decision is DispositionDecision.rejected
    assert artifact.decisions[0].reason == "Not today"
    assert artifact.trace.find(artifact.decisions[0].tool_call_id) is None


def test_no_decision_and_no_terminal_stops_before_running(
    alert_file, tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    out = tmp_path / "run.json"
    assert main(["triage", str(alert_file), "--scripted", "-o", str(out)]) == 2
    assert not out.exists()
    assert "--accept" in capsys.readouterr().err


def test_tier1_runs_and_the_proposal_is_denied(alert_file, tmp_path):
    out = tmp_path / "run.json"
    assert (
        main(
            ["triage", str(alert_file), "--scripted", "--accept", "--role", "tier1", "-o", str(out)]
        )
        == 0
    )
    artifact = RunArtifact.model_validate_json(out.read_text())
    assert artifact.role == "tier1"
    propose = artifact.trace.find(artifact.decisions[0].tool_call_id)
    assert propose is not None and propose.outcome is ToolOutcome.denied


def test_a_missing_provider_is_a_clear_error(alert_file, tmp_path, capsys):
    out = tmp_path / "run.json"
    code = main(
        ["triage", str(alert_file), "--model", "nosuchprovider:model", "--accept", "-o", str(out)]
    )
    assert code == 2
    assert not out.exists()
    assert "nosuchprovider" in capsys.readouterr().err


def test_the_terminal_prompt_accepts_or_rejects_with_a_reason(monkeypatch, capsys):
    from alert_forensics.cli import _ask_on_terminal

    answers = iter(["x", "r", "  Needs the VPN log  "])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    decision = _ask_on_terminal({"verdict": "false_positive", "recommended_action": "Close."})
    assert decision.accept is False and decision.reason == "Needs the VPN log"
    assert "false_positive" in capsys.readouterr().out
    answers = iter(["accept"])
    assert _ask_on_terminal({"verdict": "true_positive"}).accept is True
