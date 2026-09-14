"""Cells: run scores aggregated per model, role and scenario, every proportion with its
interval, failure in every denominator, cost from the price table."""

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime

from pydantic import AwareDatetime, Field

from alert_forensics.contracts import ModelUsageRecord, RunOutcome
from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.evaluation.prices import PRICES, Price, cost_usd, unpriced_models
from alert_forensics.evaluation.scoring import RunScore
from alert_forensics.evaluation.stats import Proportion


class RunMeasurement(ContractModel):
    """What only the harness knew about a run: which cell it belongs to, its index, and
    the wall clock measured around the investigation."""

    scenario: NonEmptyStr
    model: NonEmptyStr
    role: NonEmptyStr
    index: StrictNonNegativeInt
    started_at: AwareDatetime
    wall_clock_s: float = Field(ge=0)


class ScoredRun(ContractModel):
    measurement: RunMeasurement
    score: RunScore
    usage: list[ModelUsageRecord]


class Spread(ContractModel):
    mean: float
    min: float
    max: float


class Money(ContractModel):
    mean: float
    total: float


class CellSummary(ContractModel):
    model: NonEmptyStr
    role: NonEmptyStr
    scenario: NonEmptyStr
    runs: StrictNonNegativeInt
    completed: Proportion
    failed: Proportion
    failed_ungrounded: Proportion
    failed_error: Proportion
    error_kinds: dict[str, int]
    verdict_accuracy: Proportion
    evidence_recall: Proportion
    """Pooled: findings reached over required findings times runs."""
    missing_context_recall: Proportion
    escalation_precision: Proportion
    escalation_recall: Proportion
    ungrounded_claim_rate: Proportion
    """Pooled over the facts of the completed runs; zero by construction."""
    loop_held: bool
    wall_clock_s: Spread
    mean_input_tokens: float
    mean_output_tokens: float
    cost_usd: Money | None
    cost_note: str | None


class Summary(ContractModel):
    generated_at: AwareDatetime
    cells: list[CellSummary]


def summarise(
    runs: Sequence[ScoredRun],
    *,
    prices: Mapping[str, Price] = PRICES,
    now: Callable[[], datetime] | None = None,
) -> Summary:
    cells: dict[tuple[str, str, str], list[ScoredRun]] = {}
    for run in runs:
        m = run.measurement
        cells.setdefault((m.model, m.role, m.scenario), []).append(run)
    return Summary(
        generated_at=(now or (lambda: datetime.now(UTC)))(),
        cells=[_cell(key, group, prices) for key, group in sorted(cells.items())],
    )


def _cell(
    key: tuple[str, str, str], runs: Sequence[ScoredRun], prices: Mapping[str, Price]
) -> CellSummary:
    model, role, scenario = key
    scores = [r.score for r in runs]
    n = len(scores)
    completed = [s for s in scores if s.outcome is RunOutcome.completed]
    ungrounded = sum(1 for s in scores if s.outcome is RunOutcome.failed_ungrounded)
    errored = sum(1 for s in scores if s.outcome is RunOutcome.failed_error)
    expected = [s for s in scores if s.escalate_expected]
    predicted = [s for s in scores if s.escalate_predicted is True]
    correct_escalations = sum(1 for s in scores if s.escalation_correct and s.escalate_expected)
    facts = sum(s.total_facts for s in completed)
    ungrounded_facts = sum(s.ungrounded_facts for s in completed)
    walls = [r.measurement.wall_clock_s for r in runs]
    # The cell's own model is checked by name, not through its usage: a run the provider
    # refused before any turn has no usage at all, and would otherwise price at zero.
    unpriced = sorted(
        ({model} if model not in prices else set())
        | {m for r in runs for m in unpriced_models(r.usage, prices)}
    )
    costs = [cost_usd(r.usage, prices) for r in runs]
    priced = [c for c in costs if c is not None]
    money = (
        Money(mean=sum(priced) / n, total=sum(priced))
        if not unpriced and len(priced) == n
        else None
    )
    return CellSummary(
        model=model,
        role=role,
        scenario=scenario,
        runs=n,
        completed=Proportion.of(len(completed), n),
        failed=Proportion.of(ungrounded + errored, n),
        failed_ungrounded=Proportion.of(ungrounded, n),
        failed_error=Proportion.of(errored, n),
        error_kinds=dict(sorted(Counter(s.error_kind for s in scores if s.error_kind).items())),
        verdict_accuracy=Proportion.of(sum(1 for s in scores if s.verdict_correct), n),
        evidence_recall=Proportion.of(
            sum(s.findings_reached for s in scores), sum(s.findings_required for s in scores)
        ),
        missing_context_recall=Proportion.of(
            sum(s.context_named for s in scores), sum(s.context_expected for s in scores)
        ),
        escalation_precision=Proportion.of(correct_escalations, len(predicted)),
        escalation_recall=Proportion.of(correct_escalations, len(expected)),
        ungrounded_claim_rate=Proportion.of(ungrounded_facts, facts),
        loop_held=ungrounded_facts == 0,
        wall_clock_s=Spread(mean=sum(walls) / n, min=min(walls), max=max(walls)),
        mean_input_tokens=sum(u.input_tokens for r in runs for u in r.usage) / n,
        mean_output_tokens=sum(u.output_tokens for r in runs for u in r.usage) / n,
        cost_usd=money,
        cost_note=("no price for " + ", ".join(unpriced)) if unpriced else None,
    )


def render_summary(summary: Summary) -> str:
    lines = [
        f"Evaluation summary, {len(summary.cells)} cell"
        f"{'' if len(summary.cells) == 1 else 's'}, generated "
        f"{summary.generated_at.astimezone().strftime('%Y-%m-%d %H:%M %Z')}."
    ]
    for cell in summary.cells:
        lines.append("")
        lines.append(
            f"Cell: {cell.model}  role: {cell.role}  scenario: {cell.scenario}  runs: {cell.runs}"
        )
        kinds = ", ".join(f"{k} {v}" for k, v in cell.error_kinds.items())
        rows: list[tuple[str, str]] = [
            ("completed", cell.completed.render()),
            ("failed", cell.failed.render()),
            ("  failed_ungrounded", cell.failed_ungrounded.render()),
            ("  failed_error", cell.failed_error.render() + (f"  ({kinds})" if kinds else "")),
            ("verdict accuracy", cell.verdict_accuracy.render()),
            ("evidence recall", cell.evidence_recall.render()),
            ("missing context recall", cell.missing_context_recall.render()),
            ("escalation precision", cell.escalation_precision.render()),
            ("escalation recall", cell.escalation_recall.render()),
            (
                "ungrounded claim rate",
                cell.ungrounded_claim_rate.render()
                + (
                    "  over completed runs; the loop held"
                    if cell.loop_held
                    else "  THE LOOP DID NOT HOLD"
                ),
            ),
            (
                "wall clock s",
                f"mean {cell.wall_clock_s.mean:.2f}  min {cell.wall_clock_s.min:.2f}  "
                f"max {cell.wall_clock_s.max:.2f}",
            ),
            (
                "tokens per run",
                f"input {cell.mean_input_tokens:.0f}  output {cell.mean_output_tokens:.0f}",
            ),
            (
                "cost usd",
                f"mean {cell.cost_usd.mean:.4f}  total {cell.cost_usd.total:.4f}"
                if cell.cost_usd is not None
                else (cell.cost_note or "n/a"),
            ),
        ]
        lines.extend(f"  {label:<24}{value}" for label, value in rows)
    return "\n".join(lines)
