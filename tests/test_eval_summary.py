"""Cells: failure in the denominator, intervals everywhere, cost from the eval's prices."""

from datetime import UTC, datetime

import pytest

from alert_forensics.contracts import ModelUsageRecord, RunOutcome, Verdict
from alert_forensics.contracts.trace import InputTokenDetails
from alert_forensics.evaluation import (
    PRICES,
    ContextMatch,
    FindingMatch,
    Price,
    RunMeasurement,
    RunScore,
    ScoredRun,
    cost_usd,
    render_summary,
    summarise,
)

T = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)


def score(
    *,
    outcome=RunOutcome.completed,
    correct=True,
    reached=3,
    named=1,
    escalate_expected=False,
    escalate_predicted=False,
    facts=3,
    ungrounded=0,
    error_kind=None,
):
    failed = outcome is not RunOutcome.completed
    return RunScore(
        scenario="atypical_travel",
        outcome=outcome,
        verdict_expected=Verdict.false_positive,
        verdict_observed=None if failed else Verdict.false_positive,
        verdict_correct=correct and not failed,
        findings=[
            FindingMatch(
                name=f"f{i}",
                reached=i < reached and not failed,
                fact_index=None,
                cited_tool=None,
                candidates=0,
                missed_tokens=[],
            )
            for i in range(3)
        ],
        findings_reached=0 if failed else reached,
        findings_required=3,
        context=[
            ContextMatch(name=f"c{i}", named=i < named and not failed, entry_index=None)
            for i in range(2)
        ],
        context_named=0 if failed else named,
        context_expected=2,
        escalate_expected=escalate_expected,
        escalate_predicted=None if failed else escalate_predicted,
        escalation_correct=(not failed) and escalate_expected == escalate_predicted,
        total_facts=facts,
        ungrounded_facts=ungrounded,
        error_kind=error_kind,
    )


def usage(model="scripted:demo", n=2, input_tokens=1000, output_tokens=100, cache_read=0):
    return [
        ModelUsageRecord(
            step=i,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            input_token_details=InputTokenDetails(cache_read=cache_read),
        )
        for i in range(n)
    ]


def scored(index, s, *, model="scripted:demo", wall=1.5, use=None):
    return ScoredRun(
        measurement=RunMeasurement(
            scenario="atypical_travel",
            model=model,
            role="analyst",
            index=index,
            started_at=T,
            wall_clock_s=wall,
        ),
        score=s,
        usage=use if use is not None else usage(model),
    )


def test_failed_runs_stay_in_every_denominator_and_are_split_by_outcome():
    runs = [
        scored(0, score()),
        scored(1, score(outcome=RunOutcome.failed_error, error_kind="rate_limit")),
        scored(2, score(outcome=RunOutcome.failed_ungrounded, facts=2, ungrounded=1)),
    ]
    summary = summarise(runs)
    assert len(summary.cells) == 1
    cell = summary.cells[0]
    assert (cell.model, cell.role, cell.scenario, cell.runs) == (
        "scripted:demo",
        "analyst",
        "atypical_travel",
        3,
    )
    assert (cell.completed.numerator, cell.completed.denominator) == (1, 3)
    assert (cell.failed.numerator, cell.failed.denominator) == (2, 3)
    assert (cell.failed_error.numerator, cell.failed_ungrounded.numerator) == (1, 1)
    assert cell.error_kinds == {"rate_limit": 1}
    assert (cell.verdict_accuracy.numerator, cell.verdict_accuracy.denominator) == (1, 3)
    assert (cell.evidence_recall.numerator, cell.evidence_recall.denominator) == (3, 9)
    assert (cell.missing_context_recall.numerator, cell.missing_context_recall.denominator) == (
        1,
        6,
    )
    # The ungrounded rate pools the completed runs' facts only, and the loop held.
    assert (cell.ungrounded_claim_rate.numerator, cell.ungrounded_claim_rate.denominator) == (
        0,
        3,
    )
    assert cell.loop_held is True
    assert cell.verdict_accuracy.low is not None and cell.verdict_accuracy.high is not None


def test_escalation_precision_and_recall_are_absent_when_undefined_and_ignore_failed_runs():
    no_positives = summarise([scored(0, score()), scored(1, score())])
    cell = no_positives.cells[0]
    assert cell.escalation_recall.denominator == 0 and cell.escalation_recall.estimate is None
    assert cell.escalation_precision.denominator == 0
    mixed = summarise(
        [
            scored(0, score(escalate_expected=True, escalate_predicted=True)),
            scored(1, score(escalate_expected=True, escalate_predicted=False)),
            scored(2, score(escalate_expected=False, escalate_predicted=True)),
            scored(
                3, score(escalate_expected=True, outcome=RunOutcome.failed_error, error_kind="x")
            ),
        ]
    )
    cell = mixed.cells[0]
    # Recall: one correct of three expected, the failed run counted as missed.
    assert (cell.escalation_recall.numerator, cell.escalation_recall.denominator) == (1, 3)
    # Precision: one correct of two predicted; the failed run predicted nothing.
    assert (cell.escalation_precision.numerator, cell.escalation_precision.denominator) == (1, 2)


def test_cells_are_keyed_by_model_role_and_scenario():
    runs = [scored(0, score()), scored(0, score(), model="anthropic:claude-sonnet-5")]
    summary = summarise(runs)
    assert [c.model for c in summary.cells] == ["anthropic:claude-sonnet-5", "scripted:demo"]


def test_cost_is_derived_from_the_price_table_and_absent_without_a_price():
    assert cost_usd(usage("scripted:demo")) == 0.0
    sonnet = PRICES["anthropic:claude-sonnet-5"]
    assert isinstance(sonnet, Price) and sonnet.source and sonnet.as_of
    records = usage("anthropic:claude-sonnet-5", n=1, input_tokens=1_000_000, output_tokens=0)
    assert cost_usd(records) == pytest.approx(sonnet.input_per_mtok)
    cached = usage(
        "anthropic:claude-sonnet-5",
        n=1,
        input_tokens=1_000_000,
        output_tokens=0,
        cache_read=500_000,
    )
    assert cost_usd(cached) == pytest.approx(
        0.5 * sonnet.input_per_mtok + 0.5 * sonnet.cache_read_per_mtok
    )
    assert cost_usd(usage("nobody:unpriced")) is None
    assert cost_usd([]) == 0.0


def test_the_cell_reports_cost_and_latency_per_investigation():
    runs = [scored(0, score(), wall=1.0), scored(1, score(), wall=3.0)]
    cell = summarise(runs).cells[0]
    assert (
        cell.wall_clock_s.mean == 2.0
        and cell.wall_clock_s.min == 1.0
        and cell.wall_clock_s.max == 3.0
    )
    assert cell.cost_usd is not None and cell.cost_usd.mean == 0.0 and cell.cost_usd.total == 0.0
    assert cell.cost_note is None
    assert cell.mean_input_tokens == 2000.0 and cell.mean_output_tokens == 200.0
    unpriced = summarise([scored(0, score(), model="nobody:unpriced")]).cells[0]
    assert unpriced.cost_usd is None
    assert "no price for nobody:unpriced" in (unpriced.cost_note or "")


def test_the_report_prints_every_estimate_with_its_interval():
    runs = [
        scored(0, score()),
        scored(1, score(outcome=RunOutcome.failed_error, error_kind="rate_limit")),
    ]
    text = render_summary(summarise(runs))
    assert "scripted:demo" in text and "analyst" in text and "atypical_travel" in text
    assert "verdict accuracy" in text and "1/2" in text
    assert "failed" in text and "rate_limit" in text
    assert "evidence recall" in text and "3/6" in text
    assert "escalation precision" in text and "n/a" in text
    assert "ungrounded claim rate" in text and "0/3" in text
    # Every estimate carries its interval on the same line.
    for line in text.splitlines():
        if "verdict accuracy" in line:
            assert "[" in line and "]" in line
    assert "cost" in text and "wall clock" in text
