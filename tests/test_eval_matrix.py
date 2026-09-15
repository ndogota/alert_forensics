"""``alert-forensics matrix``: the committed, derived view of a campaign. Its cells are
the summary's, count for count; its bounds are the stats module's; no model judges it."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from alert_forensics.cli import main
from alert_forensics.contracts import RunOutcome, Verdict
from alert_forensics.evaluation import (
    Campaign,
    Matrix,
    MatrixMetadata,
    RunMeasurement,
    RunScore,
    ScoredRun,
    Summary,
    build_matrix,
    load_scenarios,
    wilson,
)
from conftest import ALERT_PAYLOAD
from test_eval_summary import T, score, scored, usage

TRUTH = json.loads(Path("examples/atypical_travel.truth.json").read_text())
EXAMPLES = Path("examples")


@pytest.fixture
def scenarios(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "atypical_travel.alert.json").write_text(json.dumps(ALERT_PAYLOAD))
    (d / "atypical_travel.truth.json").write_text(json.dumps(TRUTH))
    return d


@pytest.fixture
def campaign_dir(scenarios, tmp_path, capsys):
    results = tmp_path / "results"
    argv = ["eval", "--scripted", "--scenarios", str(scenarios), "--results", str(results)]
    assert main([*argv, "--runs", "2"]) == 0
    assert main(["eval-report", str(results), "--scenarios", str(scenarios)]) == 0
    capsys.readouterr()
    return results


def test_the_matrix_cells_agree_with_the_summary_over_the_same_directory(
    campaign_dir, scenarios, tmp_path, capsys
):
    out = tmp_path / "reports" / "model-matrix.json"
    assert main(["matrix", str(campaign_dir), "-o", str(out), "--scenarios", str(scenarios)]) == 0
    assert str(out) in capsys.readouterr().out
    matrix = Matrix.model_validate_json(out.read_text())
    summary = Summary.model_validate_json((campaign_dir / "summary.json").read_text())
    assert len(matrix.cells) == len(summary.cells) == 1
    for cell in matrix.cells:
        key = (cell.model, cell.scenario)
        twin = next(c for c in summary.cells if (c.model, c.scenario) == key)
        assert (cell.runs, cell.served) == (twin.runs, twin.served) == (2, 2)
        for name in (
            "refused",
            "completed",
            "failed",
            "failed_ungrounded",
            "failed_error",
            "verdict_accuracy",
            "evidence_recall",
            "missing_context_recall",
            "escalation_precision",
            "escalation_recall",
        ):
            assert getattr(cell, name) == getattr(twin, name), name
        assert (cell.refused_before_any_turn, cell.refused_after_a_turn) == (
            twin.refused_before_any_turn,
            twin.refused_after_a_turn,
        )
        assert cell.error_kinds == twin.error_kinds
        assert (cell.calls.total, cell.calls.ok, cell.calls.error, cell.calls.denied) == (
            twin.calls.total,
            twin.calls.ok,
            twin.calls.error,
            twin.calls.denied,
        )
        assert cell.calls.no_fixture == twin.calls.no_fixture.numerator
        assert cell.calls.runs_with_gaps == twin.calls.runs_with_gaps
        assert cell.cost_usd == twin.cost_usd and cell.cost_note == twin.cost_note
        assert cell.wall_clock_s == twin.wall_clock_s
    assert matrix.metadata.fixture_digest == summary.fixture_digest is not None


def test_a_proportion_in_the_file_carries_the_stats_modules_bounds(
    campaign_dir, scenarios, tmp_path, capsys
):
    out = tmp_path / "model-matrix.json"
    assert main(["matrix", str(campaign_dir), "-o", str(out), "--scenarios", str(scenarios)]) == 0
    raw = json.loads(out.read_text())
    cell = raw["cells"][0]
    for name in ("completed", "verdict_accuracy", "evidence_recall"):
        p = cell[name]
        low, high = wilson(p["numerator"], p["denominator"])
        assert p["low"] == pytest.approx(low) and p["high"] == pytest.approx(high)
        assert p["estimate"] == pytest.approx(p["numerator"] / p["denominator"])
    rollup = raw["by_model"][0]
    p = rollup["evidence_recall"]
    assert (p["low"], p["high"]) == pytest.approx(wilson(p["numerator"], p["denominator"]))


def test_the_metadata_says_no_model_judges_and_names_the_campaign(
    campaign_dir, scenarios, tmp_path, capsys
):
    out = tmp_path / "model-matrix.json"
    assert main(["matrix", str(campaign_dir), "-o", str(out), "--scenarios", str(scenarios)]) == 0
    raw = json.loads(out.read_text())
    meta = raw["metadata"]
    assert "judge_model" in meta and meta["judge_model"] is None
    assert "deterministic" in meta["judge_note"] and "no model" in meta["judge_note"]
    assert meta["models"] == ["scripted:demo"]
    assert meta["runs_per_cell"] == 2
    assert meta["scenario_ids"] == ["atypical_travel"]
    assert meta["role"] == "analyst"
    campaign = Campaign.model_validate_json((campaign_dir / "campaign.json").read_text())
    assert meta["fixture_digest"] == campaign.fixture_digest
    assert datetime.fromisoformat(meta["campaign_started_at"]) == campaign.started_at
    assert datetime.fromisoformat(meta["generated_at"]).tzinfo is not None
    (scenario,) = meta["scenarios"]
    assert scenario["name"] == "atypical_travel"
    assert scenario["title"] == ALERT_PAYLOAD["title"]
    assert scenario["verdict"] == TRUTH["verdict"] and scenario["escalate"] == TRUTH["escalate"]
    assert scenario["required_findings"] == len(TRUTH["required_findings"])
    assert scenario["missing_context"] == len(TRUTH["missing_context"])


def test_each_cell_carries_one_row_per_run_with_the_verdict_and_confidence(
    campaign_dir, scenarios, tmp_path, capsys
):
    out = tmp_path / "model-matrix.json"
    assert main(["matrix", str(campaign_dir), "-o", str(out), "--scenarios", str(scenarios)]) == 0
    matrix = Matrix.model_validate_json(out.read_text())
    (cell,) = matrix.cells
    assert [row.index for row in cell.per_run] == [0, 1]
    for row in cell.per_run:
        run_dir = campaign_dir / "scripted-demo" / "analyst" / "atypical_travel" / str(row.index)
        score_file = RunScore.model_validate_json((run_dir / "score.json").read_text())
        artifact = json.loads((run_dir / "run.json").read_text())
        assert row.outcome is RunOutcome.completed and row.refused is False
        assert row.verdict is Verdict.inconclusive
        assert row.confidence == artifact["report"]["result"]["confidence"]
        assert row.escalate == artifact["report"]["result"]["escalate"]
        assert row.tool_calls == score_file.calls.total > 0
        assert row.ok_calls == score_file.calls.ok
        assert (row.findings_reached, row.findings_required) == (0, 3)
        assert (row.context_named, row.context_expected) == (0, 2)
        assert row.wall_clock_s > 0


def _examples(*names):
    return [s for s in load_scenarios(EXAMPLES) if s.name in names]


def _in(scenario, run):
    return ScoredRun(
        measurement=run.measurement.model_copy(update={"scenario": scenario}),
        score=run.score.model_copy(update={"scenario": scenario}),
        usage=run.usage,
        confidence=0.5,
    )


def test_the_rollup_pools_a_models_cells_over_its_served_runs():
    travel = [
        scored(0, score(reached=3), wall=1.0),
        scored(1, score(outcome=RunOutcome.failed_ungrounded, facts=2, ungrounded=1), wall=3.0),
        scored(2, score(error_kind="rate_limit", outcome=RunOutcome.failed_error), wall=0.2),
    ]
    spray = [
        _in("password_spray", scored(0, score(reached=1, correct=False), wall=2.0)),
        _in("password_spray", scored(1, score(reached=2), wall=4.0)),
    ]
    matrix = build_matrix(
        [*travel, *spray],
        _examples("atypical_travel", "password_spray"),
        campaign=None,
        now=lambda: T,
    )
    # Served runs per cell, not runs: the travel cell holds three runs and two served.
    assert matrix.metadata.runs_per_cell == 2
    assert matrix.metadata.campaign_started_at is None
    assert [c.scenario for c in matrix.cells] == ["atypical_travel", "password_spray"]
    (rollup,) = matrix.by_model
    assert rollup.model == "scripted:demo" and rollup.cells == 2
    assert (rollup.runs, rollup.served) == (5, 4)
    assert (rollup.refused.numerator, rollup.refused.denominator) == (1, 5)
    assert rollup.refused_before_any_turn == 1 and rollup.refused_kinds == {"rate_limit": 1}
    assert (rollup.completed.numerator, rollup.completed.denominator) == (3, 4)
    assert (rollup.failed_ungrounded.numerator, rollup.failed_ungrounded.denominator) == (1, 4)
    assert (rollup.verdict_accuracy.numerator, rollup.verdict_accuracy.denominator) == (2, 4)
    assert (rollup.evidence_recall.numerator, rollup.evidence_recall.denominator) == (6, 12)
    assert rollup.evidence_recall.low == pytest.approx(wilson(6, 12)[0])
    assert (rollup.missing_context_recall.numerator, rollup.missing_context_recall.denominator) == (
        3,
        8,
    )
    assert rollup.calls.total == sum(c.calls.total for c in matrix.cells)
    assert rollup.wall_clock_s is not None
    assert rollup.wall_clock_s.mean == pytest.approx((1.0 + 3.0 + 2.0 + 4.0) / 4)
    assert (rollup.wall_clock_s.min, rollup.wall_clock_s.max) == (1.0, 4.0)
    assert rollup.cost_usd is not None and rollup.cost_usd.total == 0.0
    assert rollup.cost_usd.mean == 0.0


def test_a_model_unpriced_in_one_cell_has_no_rollup_cost():
    runs = [
        scored(0, score()),
        _in("password_spray", scored(0, score(), model="nobody:knows", use=usage("nobody:knows"))),
    ]
    matrix = build_matrix(runs, _examples("atypical_travel", "password_spray"), campaign=None)
    unpriced = next(r for r in matrix.by_model if r.model == "nobody:knows")
    assert unpriced.cost_usd is None and unpriced.cost_note == "no price for nobody:knows"
    priced = next(r for r in matrix.by_model if r.model == "scripted:demo")
    assert priced.cost_usd is not None


def test_a_directory_of_two_roles_is_refused(campaign_dir, scenarios, tmp_path, capsys):
    tier1 = ScoredRun(
        measurement=RunMeasurement(
            scenario="atypical_travel",
            model="scripted:demo",
            role="tier1",
            index=0,
            started_at=T,
            wall_clock_s=1.0,
        ),
        score=score(),
        usage=usage(),
    )
    with pytest.raises(ValueError, match="analyst, tier1"):
        build_matrix([scored(0, score()), tier1], _examples("atypical_travel"), campaign=None)
    # Through the command: a second role's run directory beside the first.
    src = campaign_dir / "scripted-demo" / "analyst" / "atypical_travel" / "0"
    dst = campaign_dir / "scripted-demo" / "tier1" / "atypical_travel" / "0"
    dst.parent.mkdir(parents=True)
    for name in ("run.json", "eval.json"):
        (dst / name).parent.mkdir(exist_ok=True)
        text = (src / name).read_text()
        (dst / name).write_text(text.replace('"role": "analyst"', '"role": "tier1"'))
    out = tmp_path / "model-matrix.json"
    assert main(["matrix", str(campaign_dir), "-o", str(out), "--scenarios", str(scenarios)]) == 2
    assert "analyst, tier1" in capsys.readouterr().err
    assert not out.exists()


def test_the_command_refuses_what_eval_report_refuses(scenarios, tmp_path, capsys):
    out = tmp_path / "model-matrix.json"
    empty = tmp_path / "nothing"
    assert main(["matrix", str(empty), "-o", str(out), "--scenarios", str(scenarios)]) == 2
    assert "no run" in capsys.readouterr().err
    assert not out.exists()


def test_the_matrix_contract_holds_its_judge_to_null():
    matrix = build_matrix([scored(0, score())], _examples("atypical_travel"), campaign=None)
    assert matrix.metadata.judge_model is None
    dumped = matrix.model_dump(mode="json")
    assert dumped["metadata"]["judge_model"] is None
    assert datetime.fromisoformat(dumped["metadata"]["generated_at"]).astimezone(UTC)
    with pytest.raises(ValueError):
        MatrixMetadata.model_validate({**dumped["metadata"], "judge_model": "some:model"})
