"""Cells: failure in the denominator, intervals everywhere, cost from the eval's prices."""

from datetime import UTC, datetime

import pytest

from alert_forensics.contracts import ModelUsageRecord, RunOutcome, Verdict
from alert_forensics.contracts.trace import InputTokenDetails
from alert_forensics.evaluation import (
    PRICES,
    CallOutcomes,
    CellSummary,
    ContextMatch,
    FindingMatch,
    Price,
    Proportion,
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
    calls=None,
    model_turns=None,
):
    failed = outcome is not RunOutcome.completed
    refused = error_kind in {"rate_limit", "overloaded"}
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
        refused=refused,
        model_turns=(0 if refused else 2) if model_turns is None else model_turns,
        calls=calls if calls is not None else outcomes(ok=6),
    )


def outcomes(ok, no_fixture=0, errors=None, denials=None):
    error_kinds = {**(errors or {})}
    if no_fixture:
        error_kinds["no_fixture"] = no_fixture
    denial_kinds = denials or {}
    return CallOutcomes(
        total=ok + sum(error_kinds.values()) + sum(denial_kinds.values()),
        ok=ok,
        error=sum(error_kinds.values()),
        denied=sum(denial_kinds.values()),
        no_fixture=no_fixture,
        error_kinds=dict(sorted(error_kinds.items())),
        denial_kinds=dict(sorted(denial_kinds.items())),
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
        scored(1, score(outcome=RunOutcome.failed_error, error_kind="no_result")),
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
    assert cell.error_kinds == {"no_result": 1}
    assert cell.served == 3 and cell.refused.numerator == 0
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
    assert cell.wall_clock_s is not None
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
        scored(1, score(outcome=RunOutcome.failed_error, error_kind="no_result")),
    ]
    text = render_summary(summarise(runs))
    assert "scripted:demo" in text and "analyst" in text and "atypical_travel" in text
    assert "verdict accuracy" in text and "1/2" in text
    assert "failed" in text and "no_result" in text
    assert "evidence recall" in text and "3/6" in text
    assert "escalation precision" in text and "n/a" in text
    assert "ungrounded claim rate" in text and "0/3" in text
    # Every estimate carries its interval on the same line.
    for line in text.splitlines():
        if "verdict accuracy" in line:
            assert "[" in line and "]" in line
    assert "cost" in text and "wall clock" in text


def test_tool_outcomes_are_pooled_per_cell_and_no_fixture_is_separated():
    runs = [
        scored(0, score(calls=outcomes(ok=5))),
        scored(
            1,
            score(calls=outcomes(ok=3, no_fixture=2, errors={"invalid_arguments": 1})),
        ),
        scored(
            2,
            score(
                outcome=RunOutcome.failed_error,
                error_kind="no_result",
                calls=outcomes(ok=1, denials={"scope_denied": 1}),
            ),
        ),
    ]
    cell = summarise(runs).cells[0]
    calls = cell.calls
    assert (calls.total, calls.ok, calls.error, calls.denied) == (13, 9, 3, 1)
    assert (calls.no_fixture.numerator, calls.no_fixture.denominator) == (2, 13)
    assert calls.no_fixture.low is not None
    assert calls.error_kinds == {"invalid_arguments": 1, "no_fixture": 2}
    assert calls.denial_kinds == {"scope_denied": 1}
    assert calls.runs_with_gaps == 1
    # The run's own error kind is still its own number, not mixed with the calls.
    assert cell.error_kinds == {"no_result": 1}


def test_the_report_marks_the_recall_line_when_the_cell_has_fixture_gaps():
    gaps = render_summary(summarise([scored(0, score(calls=outcomes(ok=4, no_fixture=2)))]))
    assert "tool calls" in gaps and "no_fixture" in gaps and "2/6" in gaps
    recall = next(line for line in gaps.splitlines() if "evidence recall" in line)
    assert "2 no_fixture" in recall and "floor" in recall
    clean = render_summary(summarise([scored(0, score())]))
    recall = next(line for line in clean.splitlines() if "evidence recall" in line)
    assert "no_fixture" not in recall
    assert "tool calls" in clean and "0/6" in clean


# --- a provider refusal is the quota's number ------------------------------------------


def refused(index, kind="rate_limit", *, turns=0, wall=0.2, use=None):
    """A run the provider refused: before any turn when ``turns`` is 0, after work
    otherwise."""
    return scored(
        index,
        score(outcome=RunOutcome.failed_error, error_kind=kind, model_turns=turns),
        wall=wall,
        use=use if use is not None else usage(n=turns),
    )


def test_a_provider_refusal_leaves_every_accuracy_denominator_and_is_reported_apart():
    runs = [
        scored(0, score()),
        refused(1),
        refused(2, "overloaded", turns=2, use=usage(n=2, input_tokens=500, output_tokens=50)),
        scored(3, score(outcome=RunOutcome.failed_error, error_kind="no_result")),
    ]
    cell = summarise(runs).cells[0]
    assert cell.runs == 4 and cell.served == 2
    assert (cell.refused.numerator, cell.refused.denominator) == (2, 4)
    assert cell.refused.low is not None and cell.refused.high is not None
    assert cell.refused_kinds == {"overloaded": 1, "rate_limit": 1}
    assert cell.refused_before_any_turn == 1 and cell.refused_after_a_turn == 1
    # The run's own failures keep the old rule, over the served runs.
    assert cell.error_kinds == {"no_result": 1}
    assert (cell.completed.numerator, cell.completed.denominator) == (1, 2)
    assert (cell.failed.numerator, cell.failed.denominator) == (1, 2)
    assert (cell.failed_error.numerator, cell.failed_error.denominator) == (1, 2)
    assert (cell.failed_ungrounded.numerator, cell.failed_ungrounded.denominator) == (0, 2)
    assert (cell.verdict_accuracy.numerator, cell.verdict_accuracy.denominator) == (1, 2)
    assert (cell.evidence_recall.numerator, cell.evidence_recall.denominator) == (3, 6)
    assert (cell.missing_context_recall.numerator, cell.missing_context_recall.denominator) == (
        1,
        4,
    )
    # Tool calls are the one pool a refused run stays in: it read every trace.
    assert cell.calls.total == 24
    text = render_summary(summarise(runs))
    served = next(line for line in text.splitlines() if line.strip().startswith("served"))
    assert "2 of 4" in served and "2 refused" in served and "served runs" in served
    refused_line = next(line for line in text.splitlines() if line.strip().startswith("refused"))
    assert "2/4" in refused_line and "rate_limit 1" in refused_line
    assert "1 before any model turn" in refused_line and "1 after" in refused_line
    assert "quota" in refused_line.lower() or "capacity" in refused_line.lower()


def test_escalation_ignores_refused_runs_where_it_counted_failed_ones():
    # The refused run's truth expects an escalation too, and it is not a missed one.
    runs = [
        scored(0, score(escalate_expected=True, escalate_predicted=True)),
        scored(
            1,
            score(escalate_expected=True, outcome=RunOutcome.failed_error, error_kind="rate_limit"),
            use=[],
        ),
        scored(2, score(escalate_expected=True, outcome=RunOutcome.failed_error, error_kind="x")),
    ]
    cell = summarise(runs).cells[0]
    assert (cell.escalation_recall.numerator, cell.escalation_recall.denominator) == (1, 2)
    assert (cell.escalation_precision.numerator, cell.escalation_precision.denominator) == (1, 1)


def test_latency_and_tokens_are_over_served_runs_and_the_line_says_so():
    runs = [
        scored(0, score(), wall=5.6, use=usage(n=1, input_tokens=11768, output_tokens=141)),
        refused(1, wall=0.17),
        refused(2, wall=0.2),
        refused(3, turns=2, wall=3.4, use=usage(n=2, input_tokens=2935, output_tokens=40)),
    ]
    cell = summarise(runs).cells[0]
    assert cell.wall_clock_s is not None
    assert (cell.wall_clock_s.mean, cell.wall_clock_s.min, cell.wall_clock_s.max) == (
        5.6,
        5.6,
        5.6,
    )
    assert cell.mean_input_tokens == 11768.0 and cell.mean_output_tokens == 141.0
    assert cell.refused_input_tokens == 5870 and cell.refused_output_tokens == 80
    # The scripted price is zero, so the money is zero; the populations are what is checked.
    assert cell.cost_usd is not None and cell.cost_usd.mean == 0.0 and cell.cost_usd.total == 0.0
    text = render_summary(summarise(runs))
    lines = {line.strip().split("  ")[0]: line for line in text.splitlines()}
    assert "over 1 served run" in lines["wall clock s"] and "5.60" in lines["wall clock s"]
    assert "over 1 served run" in lines["tokens per run"] and "11768" in lines["tokens per run"]
    assert "refused runs spent" in lines["tokens per run"] and "5870" in lines["tokens per run"]
    assert "per served run" in lines["cost usd"] and "over all 4 runs" in lines["cost usd"]


def test_a_cell_with_no_served_run_is_marked_as_a_quota_cell():
    runs = [refused(0), refused(1), refused(2)]
    cell = summarise(runs).cells[0]
    assert cell.served == 0 and cell.refused.numerator == 3
    assert cell.completed.denominator == 0 and cell.completed.estimate is None
    assert cell.verdict_accuracy.denominator == 0 and cell.evidence_recall.denominator == 0
    assert cell.wall_clock_s is None
    assert cell.mean_input_tokens is None and cell.mean_output_tokens is None
    assert cell.cost_usd is not None and cell.cost_usd.mean is None and cell.cost_usd.total == 0.0
    text = render_summary(summarise(runs))
    served = next(line for line in text.splitlines() if line.strip().startswith("served"))
    assert "0 of 3" in served and "QUOTA" in served and "NOT THE MODEL" in served
    assert "0/0 n/a" in next(line for line in text.splitlines() if "verdict accuracy" in line)
    assert "no served run" in next(line for line in text.splitlines() if "wall clock" in line)
    assert "refused runs spent" not in text


def test_the_cell_holds_served_plus_refused_to_its_runs_and_every_denominator_to_served():
    cell = summarise([scored(0, score()), refused(1)]).cells[0]
    payload = cell.model_dump()
    with pytest.raises(ValueError, match="served"):
        CellSummary.model_validate({**payload, "served": 2})
    with pytest.raises(ValueError, match="served"):
        CellSummary.model_validate(
            {**payload, "verdict_accuracy": Proportion.of(1, 2).model_dump()}
        )
    with pytest.raises(ValueError, match="refus"):
        CellSummary.model_validate({**payload, "error_kinds": {"rate_limit": 1}})


def test_the_flash_lite_row_is_priced_from_the_pricing_page_not_from_memory():
    price = PRICES["google_genai:gemini-3.5-flash-lite"]
    assert "ai.google.dev/gemini-api/docs/pricing" in price.source
    assert price.as_of == "2026-09-15" and "2026-09-15" in price.source
    assert (price.input_per_mtok, price.output_per_mtok, price.cache_read_per_mtok) == (
        0.30,
        2.50,
        0.03,
    )
    assert price.cache_write_per_mtok == price.input_per_mtok and "storage" in price.source
    records = usage(
        "google_genai:gemini-3.5-flash-lite", n=1, input_tokens=1_000_000, output_tokens=0
    )
    assert cost_usd(records) == pytest.approx(0.30)
    cell = summarise([scored(0, score(), model="google_genai:gemini-3.5-flash-lite")]).cells[0]
    assert cell.cost_note is None and cell.cost_usd is not None


OPENAI_PRICING = "developers.openai.com/api/docs/pricing"
ANTHROPIC_PRICING = "platform.claude.com/docs/en/about-claude/pricing"
PRICED_ON = "2026-09-15"


@pytest.mark.parametrize(
    ("model", "page", "expected"),
    [
        # (input, output, cache read, cache write) per million, as read from the page.
        ("openai:gpt-5-nano", OPENAI_PRICING, (0.05, 0.40, 0.005, 0.0)),
        ("openai:gpt-5-mini", OPENAI_PRICING, (0.25, 2.00, 0.025, 0.0)),
        ("anthropic:claude-haiku-4-5", ANTHROPIC_PRICING, (1.0, 5.0, 0.10, 1.25)),
        ("anthropic:claude-sonnet-5", ANTHROPIC_PRICING, (2.0, 10.0, 0.20, 2.50)),
    ],
)
def test_the_probed_models_are_priced_from_their_provider_pages_not_from_memory(
    model, page, expected
):
    price = PRICES[model]
    assert page in price.source and PRICED_ON in price.source
    assert price.as_of == PRICED_ON
    assert (
        price.input_per_mtok,
        price.output_per_mtok,
        price.cache_read_per_mtok,
        price.cache_write_per_mtok,
    ) == expected
    records = usage(model, n=1, input_tokens=1_000_000, output_tokens=0)
    assert cost_usd(records) == pytest.approx(expected[0])
    cell = summarise([scored(0, score(), model=model)]).cells[0]
    assert cell.cost_note is None and cell.cost_usd is not None


def test_no_price_row_is_sourced_from_a_cached_reference():
    for model, price in PRICES.items():
        if model.startswith("scripted:"):
            continue
        assert "cached" not in price.source.split("read")[0], model
        assert "https://" in price.source, model
