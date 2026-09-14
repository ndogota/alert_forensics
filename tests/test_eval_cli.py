"""``alert-forensics eval`` and ``eval-report``: files per run, a derived summary, no socket."""

import json
import shutil
from pathlib import Path

import pytest

from alert_forensics.artifact import RunArtifact
from alert_forensics.cli import main
from alert_forensics.contracts import RunOutcome
from alert_forensics.evaluation import RunMeasurement, RunScore, Summary
from conftest import ALERT_PAYLOAD, RefusingChatModel

TRUTH = json.loads(Path("examples/atypical_travel.truth.json").read_text())


@pytest.fixture
def scenarios(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "atypical_travel.alert.json").write_text(json.dumps(ALERT_PAYLOAD))
    (d / "atypical_travel.truth.json").write_text(json.dumps(TRUTH))
    return d


def test_eval_scripted_writes_every_run_and_a_derived_summary(scenarios, tmp_path, capsys):
    results = tmp_path / "results"
    code = main(
        [
            "eval",
            "--scripted",
            "--runs",
            "2",
            "--scenarios",
            str(scenarios),
            "--results",
            str(results),
        ]
    )
    assert code == 0
    cell = results / "scripted-demo" / "analyst" / "atypical_travel"
    assert sorted(p.name for p in cell.iterdir()) == ["0", "1"]
    for k in ("0", "1"):
        run_dir = cell / k
        artifact = RunArtifact.model_validate_json((run_dir / "run.json").read_text())
        assert artifact.outcome is RunOutcome.completed
        assert artifact.model == "scripted:demo"
        assert (run_dir / artifact.raw_store).is_dir()
        measurement = RunMeasurement.model_validate_json((run_dir / "eval.json").read_text())
        assert measurement.scenario == "atypical_travel" and measurement.index == int(k)
        assert measurement.model == "scripted:demo" and measurement.role == "analyst"
        assert measurement.wall_clock_s > 0
        score = RunScore.model_validate_json((run_dir / "score.json").read_text())
        assert score.verdict_correct is False  # inconclusive by construction
        assert score.findings_reached == 0 and score.context_named == 0
        assert score.escalation_correct is True
    summary = Summary.model_validate_json((results / "summary.json").read_text())
    assert len(summary.cells) == 1
    cell_summary = summary.cells[0]
    assert cell_summary.runs == 2
    assert cell_summary.completed.numerator == 2
    assert cell_summary.verdict_accuracy.numerator == 0
    assert cell_summary.evidence_recall.denominator == 6
    assert cell_summary.cost_usd is not None and cell_summary.cost_usd.total == 0.0
    assert cell_summary.calls.total == 2 * score.calls.total > 0
    assert cell_summary.calls.no_fixture.numerator == 0 and cell_summary.calls.runs_with_gaps == 0
    captured = capsys.readouterr()
    assert "verdict accuracy" in captured.out and "0/2" in captured.out
    assert "tool calls" in captured.out
    assert "[" in captured.out
    # Progress, one line per run, on stderr.
    assert captured.err.count("atypical_travel") == 2
    assert "completed" in captured.err


def test_show_and_replay_read_the_harness_artifact(scenarios, tmp_path, capsys):
    results = tmp_path / "results"
    main(
        [
            "eval",
            "--scripted",
            "--runs",
            "1",
            "--scenarios",
            str(scenarios),
            "--results",
            str(results),
        ]
    )
    capsys.readouterr()
    run = results / "scripted-demo" / "analyst" / "atypical_travel" / "0" / "run.json"
    assert main(["show", str(run)]) == 0
    assert main(["replay", str(run)]) == 0
    assert "raw responses verified" in capsys.readouterr().out


def test_eval_report_recomputes_the_summary_from_the_current_truth(scenarios, tmp_path, capsys):
    results = tmp_path / "results"
    main(
        [
            "eval",
            "--scripted",
            "--runs",
            "1",
            "--scenarios",
            str(scenarios),
            "--results",
            str(results),
        ]
    )
    (results / "summary.json").unlink()
    score_file = results / "scripted-demo" / "analyst" / "atypical_travel" / "0" / "score.json"
    before = RunScore.model_validate_json(score_file.read_text())
    assert before.findings_reached == 0
    # The owner widens a finding; the old runs re-score without a model.
    widened = json.loads((scenarios / "atypical_travel.truth.json").read_text())
    widened["required_findings"][2]["tokens"] = ["Atypical travel"]
    (scenarios / "atypical_travel.truth.json").write_text(json.dumps(widened))
    capsys.readouterr()
    assert main(["eval-report", str(results), "--scenarios", str(scenarios)]) == 0
    after = RunScore.model_validate_json(score_file.read_text())
    assert after.findings_reached == 1
    summary = Summary.model_validate_json((results / "summary.json").read_text())
    assert summary.cells[0].evidence_recall.numerator == 1
    assert "1/3" in capsys.readouterr().out


def test_eval_report_on_an_empty_directory_says_so(tmp_path, scenarios, capsys):
    assert main(["eval-report", str(tmp_path / "nothing"), "--scenarios", str(scenarios)]) == 2
    assert "no run" in capsys.readouterr().err


def test_runs_from_several_sessions_summarise_together(scenarios, tmp_path, capsys):
    results = tmp_path / "results"
    argv = [
        "eval",
        "--scripted",
        "--runs",
        "1",
        "--scenarios",
        str(scenarios),
        "--results",
        str(results),
    ]
    main(argv)
    first = results / "scripted-demo" / "analyst" / "atypical_travel" / "0"
    shutil.copytree(first, results / "scripted-demo" / "tier1" / "atypical_travel" / "0")
    meta = json.loads((first / "eval.json").read_text())
    meta["role"] = "tier1"
    (results / "scripted-demo" / "tier1" / "atypical_travel" / "0" / "eval.json").write_text(
        json.dumps(meta)
    )
    capsys.readouterr()
    assert main(["eval-report", str(results), "--scenarios", str(scenarios)]) == 0
    summary = Summary.model_validate_json((results / "summary.json").read_text())
    assert sorted((c.model, c.role) for c in summary.cells) == [
        ("scripted:demo", "analyst"),
        ("scripted:demo", "tier1"),
    ]


def test_a_refusing_provider_is_counted_as_failure_and_the_suite_goes_on(
    scenarios, tmp_path, monkeypatch, capsys
):
    from langchain_core.exceptions import ModelRateLimitError

    refusing = RefusingChatModel(exc=ModelRateLimitError("429 RESOURCE_EXHAUSTED"))
    monkeypatch.setattr("langchain.chat_models.init_chat_model", lambda *a, **k: refusing)
    results = tmp_path / "results"
    code = main(
        [
            "eval",
            "--model",
            "google_genai:gemini-x",
            "--runs",
            "2",
            "--scenarios",
            str(scenarios),
            "--results",
            str(results),
        ]
    )
    assert code == 0
    cell = results / "google_genai-gemini-x" / "analyst" / "atypical_travel"
    assert sorted(p.name for p in cell.iterdir()) == ["0", "1"]
    artifact = RunArtifact.model_validate_json((cell / "1" / "run.json").read_text())
    assert artifact.outcome is RunOutcome.failed_error
    assert artifact.error is not None and artifact.error.kind == "rate_limit"
    assert artifact.model_limits is not None and artifact.model_limits.max_retries == 1
    summary = Summary.model_validate_json((results / "summary.json").read_text())
    cell_summary = summary.cells[0]
    assert cell_summary.failed_error.numerator == 2 and cell_summary.runs == 2
    assert cell_summary.error_kinds == {"rate_limit": 2}
    assert cell_summary.verdict_accuracy.numerator == 0
    assert cell_summary.verdict_accuracy.denominator == 2
    assert cell_summary.cost_note is not None and "gemini-x" in cell_summary.cost_note
    out = capsys.readouterr().out
    assert "rate_limit" in out and "0/2" in out


def test_eval_needs_a_model_or_scripted_and_a_known_scenario(scenarios, tmp_path, capsys):
    results = tmp_path / "results"
    assert main(["eval", "--scenarios", str(scenarios), "--results", str(results)]) == 2
    assert "--model" in capsys.readouterr().err
    assert (
        main(
            [
                "eval",
                "--scripted",
                "--scenario",
                "nope",
                "--scenarios",
                str(scenarios),
                "--results",
                str(results),
            ]
        )
        == 2
    )
    assert "nope" in capsys.readouterr().err
    assert not results.exists()
    assert main(["eval", "--scripted", "--runs", "0", "--scenarios", str(scenarios)]) == 2


def test_the_scripted_suite_hits_a_stub_on_every_call_of_every_shipped_scenario(tmp_path):
    """A fixture gap in a new scenario is visible in the tool calls block before a real
    model ever runs it."""
    results = tmp_path / "results"
    assert main(["eval", "--scripted", "--runs", "1", "--results", str(results)]) == 0
    summary = Summary.model_validate_json((results / "summary.json").read_text())
    assert sorted(c.scenario for c in summary.cells) == ["atypical_travel", "password_spray"]
    for cell in summary.cells:
        assert cell.completed.numerator == 1, cell.scenario
        assert cell.calls.no_fixture.numerator == 0, (cell.scenario, cell.calls)
        assert cell.calls.error == 0 and cell.calls.denied == 0, (cell.scenario, cell.calls)
