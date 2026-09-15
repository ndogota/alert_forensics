"""The committed view of a campaign: one JSON derived from the run directories and the
ground truth by the same scoring ``eval-report`` uses, small enough to commit while the
campaign is not. Cells are the summary's, count for count; rollups pool a model's cells
over its served runs; no model judges any of it."""

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime

from pydantic import AwareDatetime, Field, model_validator

from alert_forensics.contracts import RunOutcome, Verdict
from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.evaluation.harness import Campaign
from alert_forensics.evaluation.prices import PRICES, Price
from alert_forensics.evaluation.stats import Proportion
from alert_forensics.evaluation.summary import CellSummary, Money, ScoredRun, Spread, summarise
from alert_forensics.evaluation.truth import Scenario

JUDGE_NOTE = (
    "Every number here comes from deterministic scorers, a verdict compared exactly and a "
    "finding matched by the tool a fact cites and whole-word tokens; no model judges any run."
)


class MatrixCalls(ContractModel):
    """Tool calls pooled over the runs, refused runs included, with ``no_fixture`` as a
    count beside the recall, never a threshold."""

    total: StrictNonNegativeInt
    ok: StrictNonNegativeInt
    error: StrictNonNegativeInt
    denied: StrictNonNegativeInt
    no_fixture: StrictNonNegativeInt
    runs_with_gaps: StrictNonNegativeInt


_OVER_SERVED = ("completed", "failed", "failed_ungrounded", "failed_error", "verdict_accuracy")


class Measures(ContractModel):
    """The measures a cell and a rollup share. Every proportion is the summary's
    ``Proportion``, so its bounds are the stats module's and the validator refuses any
    other; every accuracy denominator is the served run count."""

    runs: StrictNonNegativeInt
    served: StrictNonNegativeInt
    refused: Proportion
    refused_kinds: dict[str, int]
    refused_before_any_turn: StrictNonNegativeInt
    refused_after_a_turn: StrictNonNegativeInt
    completed: Proportion
    failed: Proportion
    failed_ungrounded: Proportion
    failed_error: Proportion
    error_kinds: dict[str, int]
    verdict_accuracy: Proportion
    evidence_recall: Proportion
    missing_context_recall: Proportion
    escalation_precision: Proportion
    escalation_recall: Proportion
    calls: MatrixCalls
    wall_clock_s: Spread | None
    """Over the served runs; absent without any."""
    cost_usd: Money | None
    cost_note: str | None

    @model_validator(mode="after")
    def _the_two_populations_agree(self) -> "Measures":
        if (
            self.served + self.refused.numerator != self.runs
            or self.refused.denominator != self.runs
        ):
            raise ValueError("served plus refused is the run count, and refused is over the runs")
        for name in _OVER_SERVED:
            if getattr(self, name).denominator != self.served:
                raise ValueError(f"{name} is over the served runs")
        if (self.served == 0) != (self.wall_clock_s is None):
            raise ValueError("the wall clock is over the served runs and absent without any")
        return self


class RunRow(ContractModel):
    """One run of a cell, in index order: what it did, so a page can name a run's
    verdict, confidence and call count from this file rather than from a directory
    that is not committed."""

    index: StrictNonNegativeInt
    outcome: RunOutcome
    refused: bool
    error_kind: str | None
    verdict: Verdict | None
    """The result's verdict whatever the outcome, as the score carries it; absent when
    the run produced no result."""
    confidence: float | None = Field(ge=0, le=1)
    escalate: bool | None
    """As the score reads it: absent on a failed run, which predicted nothing."""
    tool_calls: StrictNonNegativeInt
    ok_calls: StrictNonNegativeInt
    no_fixture: StrictNonNegativeInt
    findings_reached: StrictNonNegativeInt
    findings_required: StrictNonNegativeInt
    context_named: StrictNonNegativeInt
    context_expected: StrictNonNegativeInt
    wall_clock_s: float = Field(ge=0)


class MatrixCell(Measures):
    model: NonEmptyStr
    scenario: NonEmptyStr
    per_run: list[RunRow]


class ModelRollup(Measures):
    model: NonEmptyStr
    cells: StrictNonNegativeInt


class ScenarioMeta(ContractModel):
    """What the ground truth says about a scenario, read from the truth file so a page
    names no truth it did not read."""

    name: NonEmptyStr
    title: NonEmptyStr
    verdict: Verdict
    escalate: bool
    required_findings: StrictNonNegativeInt
    missing_context: StrictNonNegativeInt


class MatrixMetadata(ContractModel):
    models: list[NonEmptyStr]
    runs_per_cell: int | None
    """The served count every cell holds; None when cells differ, and then each cell's
    ``served`` says."""
    scenario_ids: list[NonEmptyStr]
    scenarios: list[ScenarioMeta]
    role: NonEmptyStr
    fixture_digest: str | None
    campaign_started_at: AwareDatetime | None
    generated_at: AwareDatetime
    judge_model: None = None
    """Null, structurally: a reader arriving from pod_forensics looks for this field."""
    judge_note: NonEmptyStr


class Matrix(ContractModel):
    metadata: MatrixMetadata
    cells: list[MatrixCell]
    by_model: list[ModelRollup]


def build_matrix(
    runs: Sequence[ScoredRun],
    scenarios: Sequence[Scenario],
    *,
    campaign: Campaign | None,
    prices: Mapping[str, Price] = PRICES,
    now: Callable[[], datetime] | None = None,
) -> Matrix:
    """The matrix over ``runs``, one role, one fixture revision. The summary is built by
    ``summarise`` and projected cell by cell; the rollups pool each model's cells."""
    summary = summarise(runs, prices=prices, now=now)
    if not summary.cells:
        raise ValueError("no run to build a matrix from")
    roles = sorted({c.role for c in summary.cells})
    if len(roles) > 1:
        raise ValueError(
            "the runs are under more than one role and a matrix is one role: " + ", ".join(roles)
        )
    by_name = {s.name: s for s in scenarios}
    grouped: dict[tuple[str, str], list[ScoredRun]] = {}
    for run in runs:
        grouped.setdefault((run.measurement.model, run.measurement.scenario), []).append(run)
    cells = [
        _cell(c, sorted(grouped[(c.model, c.scenario)], key=lambda r: r.measurement.index))
        for c in summary.cells
    ]
    models = list(dict.fromkeys(c.model for c in cells))
    scenario_ids = list(dict.fromkeys(c.scenario for c in cells))
    missing = [name for name in scenario_ids if name not in by_name]
    if missing:
        raise ValueError("no ground truth among the scenarios given for: " + ", ".join(missing))
    served = {c.served for c in cells}
    return Matrix(
        metadata=MatrixMetadata(
            models=models,
            runs_per_cell=next(iter(served)) if len(served) == 1 else None,
            scenario_ids=scenario_ids,
            scenarios=[_scenario_meta(by_name[name]) for name in scenario_ids],
            role=roles[0],
            fixture_digest=summary.fixture_digest,
            campaign_started_at=campaign.started_at if campaign is not None else None,
            generated_at=summary.generated_at,
            judge_note=JUDGE_NOTE,
        ),
        cells=cells,
        by_model=[_rollup(model, [c for c in cells if c.model == model]) for model in models],
    )


def _scenario_meta(scenario: Scenario) -> ScenarioMeta:
    truth = scenario.truth
    return ScenarioMeta(
        name=scenario.name,
        title=scenario.alert.title,
        verdict=truth.verdict,
        escalate=truth.escalate,
        required_findings=len(truth.required_findings),
        missing_context=len(truth.missing_context),
    )


def _row(run: ScoredRun) -> RunRow:
    score = run.score
    return RunRow(
        index=run.measurement.index,
        outcome=score.outcome,
        refused=score.refused,
        error_kind=score.error_kind,
        verdict=score.verdict_observed,
        confidence=run.confidence,
        escalate=score.escalate_predicted,
        tool_calls=score.calls.total,
        ok_calls=score.calls.ok,
        no_fixture=score.calls.no_fixture,
        findings_reached=score.findings_reached,
        findings_required=score.findings_required,
        context_named=score.context_named,
        context_expected=score.context_expected,
        wall_clock_s=run.measurement.wall_clock_s,
    )


def _cell(c: CellSummary, runs: Sequence[ScoredRun]) -> MatrixCell:
    return MatrixCell(
        model=c.model,
        scenario=c.scenario,
        per_run=[_row(run) for run in runs],
        runs=c.runs,
        served=c.served,
        refused=c.refused,
        refused_kinds=c.refused_kinds,
        refused_before_any_turn=c.refused_before_any_turn,
        refused_after_a_turn=c.refused_after_a_turn,
        completed=c.completed,
        failed=c.failed,
        failed_ungrounded=c.failed_ungrounded,
        failed_error=c.failed_error,
        error_kinds=c.error_kinds,
        verdict_accuracy=c.verdict_accuracy,
        evidence_recall=c.evidence_recall,
        missing_context_recall=c.missing_context_recall,
        escalation_precision=c.escalation_precision,
        escalation_recall=c.escalation_recall,
        calls=MatrixCalls(
            total=c.calls.total,
            ok=c.calls.ok,
            error=c.calls.error,
            denied=c.calls.denied,
            no_fixture=c.calls.no_fixture.numerator,
            runs_with_gaps=c.calls.runs_with_gaps,
        ),
        wall_clock_s=c.wall_clock_s,
        cost_usd=c.cost_usd,
        cost_note=c.cost_note,
    )


def _pool(cells: Sequence[Measures], name: str) -> Proportion:
    """The cells' proportion summed numerator over summed denominator: every served run,
    or every (finding, run) pair, of the model counted once."""
    return Proportion.of(
        sum(getattr(c, name).numerator for c in cells),
        sum(getattr(c, name).denominator for c in cells),
    )


def _merge(cells: Sequence[Measures], name: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for c in cells:
        counts.update(getattr(c, name))
    return dict(sorted(counts.items()))


def _rollup(model: str, cells: Sequence[MatrixCell]) -> ModelRollup:
    runs = sum(c.runs for c in cells)
    served = sum(c.served for c in cells)
    timed = [(c.wall_clock_s, c.served) for c in cells if c.wall_clock_s is not None]
    wall = (
        Spread(
            mean=sum(w.mean * n for w, n in timed) / served,
            min=min(w.min for w, _ in timed),
            max=max(w.max for w, _ in timed),
        )
        if served
        else None
    )
    notes = sorted({c.cost_note for c in cells if c.cost_note})
    priced = [c.cost_usd for c in cells if c.cost_usd is not None]
    money = None
    if not notes and len(priced) == len(cells):
        means = [
            (m.mean, c.served) for m, c in zip(priced, cells, strict=True) if m.mean is not None
        ]
        money = Money(
            mean=sum(mean * n for mean, n in means) / served if served else None,
            total=sum(m.total for m in priced),
        )
    return ModelRollup(
        model=model,
        cells=len(cells),
        runs=runs,
        served=served,
        refused=Proportion.of(sum(c.refused.numerator for c in cells), runs),
        refused_kinds=_merge(cells, "refused_kinds"),
        refused_before_any_turn=sum(c.refused_before_any_turn for c in cells),
        refused_after_a_turn=sum(c.refused_after_a_turn for c in cells),
        completed=_pool(cells, "completed"),
        failed=_pool(cells, "failed"),
        failed_ungrounded=_pool(cells, "failed_ungrounded"),
        failed_error=_pool(cells, "failed_error"),
        error_kinds=_merge(cells, "error_kinds"),
        verdict_accuracy=_pool(cells, "verdict_accuracy"),
        evidence_recall=_pool(cells, "evidence_recall"),
        missing_context_recall=_pool(cells, "missing_context_recall"),
        escalation_precision=_pool(cells, "escalation_precision"),
        escalation_recall=_pool(cells, "escalation_recall"),
        calls=MatrixCalls(
            total=sum(c.calls.total for c in cells),
            ok=sum(c.calls.ok for c in cells),
            error=sum(c.calls.error for c in cells),
            denied=sum(c.calls.denied for c in cells),
            no_fixture=sum(c.calls.no_fixture for c in cells),
            runs_with_gaps=sum(c.calls.runs_with_gaps for c in cells),
        ),
        wall_clock_s=wall,
        cost_usd=money,
        cost_note="; ".join(notes) if notes else None,
    )
