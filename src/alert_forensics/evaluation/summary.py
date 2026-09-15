"""Cells: run scores aggregated per model, role and scenario, every proportion with its
interval, failure in every denominator, a provider refusal in none of them, cost from
the price table."""

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime

from pydantic import AwareDatetime, Field, model_validator

from alert_forensics.contracts import PROVIDER_REFUSALS, ModelUsageRecord, RunOutcome
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
    fixture_digest: str | None = None
    """The fixture revision the run was handed, see ``fixture_digest``; None on a run
    made before campaigns were versioned, which cannot say."""


class ScoredRun(ContractModel):
    measurement: RunMeasurement
    score: RunScore
    usage: list[ModelUsageRecord]


class Spread(ContractModel):
    mean: float
    min: float
    max: float


class Money(ContractModel):
    mean: float | None
    """Per served run; absent when the cell has no served run."""
    total: float
    """Over every run, refused included: the tokens were billed whether or not the run
    finished."""


class CellCalls(ContractModel):
    """Tool calls pooled over a cell's runs, refused runs included: a call the model made
    is the model's whatever the provider did next. ``no_fixture`` is a proportion of all
    calls, reported beside the recall; ``runs_with_gaps`` says how many runs had at least
    one."""

    total: StrictNonNegativeInt
    ok: StrictNonNegativeInt
    error: StrictNonNegativeInt
    denied: StrictNonNegativeInt
    no_fixture: Proportion
    runs_with_gaps: StrictNonNegativeInt
    error_kinds: dict[str, int]
    denial_kinds: dict[str, int]


_OVER_SERVED = ("completed", "failed", "failed_ungrounded", "failed_error", "verdict_accuracy")
"""The proportions whose denominator is the served run count, held by the validator."""


class CellSummary(ContractModel):
    model: NonEmptyStr
    role: NonEmptyStr
    scenario: NonEmptyStr
    runs: StrictNonNegativeInt
    """Every run in the cell, served or refused."""
    served: StrictNonNegativeInt
    """The runs the provider let run to their end: ``runs`` less the refused ones. The
    population of every accuracy and failure proportion below."""
    refused: Proportion
    """Runs the provider refused, over all runs: the quota's number, not the model's."""
    refused_kinds: dict[str, int]
    """``rate_limit`` and ``overloaded``, by count."""
    refused_before_any_turn: StrictNonNegativeInt
    refused_after_a_turn: StrictNonNegativeInt
    completed: Proportion
    failed: Proportion
    failed_ungrounded: Proportion
    failed_error: Proportion
    error_kinds: dict[str, int]
    """The runs' own error kinds, on failed_error runs; never a refusal kind. Tool calls
    are under ``calls``."""
    calls: CellCalls
    verdict_accuracy: Proportion
    evidence_recall: Proportion
    """Pooled over the served runs: findings reached over required findings times runs."""
    missing_context_recall: Proportion
    escalation_precision: Proportion
    escalation_recall: Proportion
    ungrounded_claim_rate: Proportion
    """Pooled over the facts of the completed runs; zero by construction."""
    loop_held: bool
    wall_clock_s: Spread | None
    """Over the served runs; absent when there is none."""
    mean_input_tokens: float | None
    mean_output_tokens: float | None
    """Per served run; absent when there is none."""
    refused_input_tokens: StrictNonNegativeInt
    refused_output_tokens: StrictNonNegativeInt
    """What the refused runs spent, kept apart from the per-investigation means."""
    cost_usd: Money | None
    cost_note: str | None

    @model_validator(mode="after")
    def _the_two_populations_agree(self) -> "CellSummary":
        if (
            self.served + self.refused.numerator != self.runs
            or self.refused.denominator != self.runs
        ):
            raise ValueError("served plus refused is the run count, and refused is over the runs")
        if self.refused_before_any_turn + self.refused_after_a_turn != self.refused.numerator:
            raise ValueError("the refused runs split by turn add up to the refused count")
        if sum(self.refused_kinds.values()) != self.refused.numerator:
            raise ValueError("the refused kinds add up to the refused count")
        for name in _OVER_SERVED:
            if getattr(self, name).denominator != self.served:
                raise ValueError(f"{name} is over the served runs")
        if PROVIDER_REFUSALS & self.error_kinds.keys():
            raise ValueError("a refusal kind is under refused_kinds, never among error_kinds")
        if (self.served == 0) != (self.wall_clock_s is None):
            raise ValueError("the wall clock is over the served runs and absent without any")
        return self


class Summary(ContractModel):
    generated_at: AwareDatetime
    fixture_digest: str | None = None
    """The one fixture revision every run was handed; None when any run predates the
    versioning of campaigns and cannot say. Two revisions never summarise together."""
    cells: list[CellSummary]


def summarise(
    runs: Sequence[ScoredRun],
    *,
    prices: Mapping[str, Price] = PRICES,
    now: Callable[[], datetime] | None = None,
) -> Summary:
    """One summary over runs of one fixture revision. Runs naming two revisions are
    refused here as well as at the directory, so a summary cannot be built over a
    pool; a run without a digest leaves the summary without one."""
    digests = {r.measurement.fixture_digest for r in runs}
    if len(digests - {None}) > 1:
        raise ValueError(
            "runs of two fixture revisions cannot be summarised together: "
            + ", ".join(sorted(d for d in digests if d is not None))
        )
    cells: dict[tuple[str, str, str], list[ScoredRun]] = {}
    for run in runs:
        m = run.measurement
        cells.setdefault((m.model, m.role, m.scenario), []).append(run)
    return Summary(
        generated_at=(now or (lambda: datetime.now(UTC)))(),
        fixture_digest=None if None in digests else next(iter(digests), None),
        cells=[_cell(key, group, prices) for key, group in sorted(cells.items())],
    )


def _cell(
    key: tuple[str, str, str], runs: Sequence[ScoredRun], prices: Mapping[str, Price]
) -> CellSummary:
    model, role, scenario = key
    n = len(runs)
    refused_runs = [r for r in runs if r.score.refused]
    served_runs = [r for r in runs if not r.score.refused]
    served = [r.score for r in served_runs]
    m = len(served)
    completed = [s for s in served if s.outcome is RunOutcome.completed]
    ungrounded = sum(1 for s in served if s.outcome is RunOutcome.failed_ungrounded)
    errored = sum(1 for s in served if s.outcome is RunOutcome.failed_error)
    expected = [s for s in served if s.escalate_expected]
    predicted = [s for s in served if s.escalate_predicted is True]
    correct_escalations = sum(1 for s in served if s.escalation_correct and s.escalate_expected)
    facts = sum(s.total_facts for s in completed)
    ungrounded_facts = sum(s.ungrounded_facts for s in completed)
    walls = [r.measurement.wall_clock_s for r in served_runs]
    calls = [r.score.calls for r in runs]
    error_kinds: Counter[str] = Counter()
    denial_kinds: Counter[str] = Counter()
    for c in calls:
        error_kinds.update(c.error_kinds)
        denial_kinds.update(c.denial_kinds)
    total_calls = sum(c.total for c in calls)
    pooled_calls = CellCalls(
        total=total_calls,
        ok=sum(c.ok for c in calls),
        error=sum(c.error for c in calls),
        denied=sum(c.denied for c in calls),
        no_fixture=Proportion.of(sum(c.no_fixture for c in calls), total_calls),
        runs_with_gaps=sum(1 for c in calls if c.no_fixture),
        error_kinds=dict(sorted(error_kinds.items())),
        denial_kinds=dict(sorted(denial_kinds.items())),
    )
    # The cell's own model is checked by name, not through its usage: a run the provider
    # refused before any turn has no usage at all, and would otherwise price at zero.
    unpriced = sorted(
        ({model} if model not in prices else set())
        | {name for r in runs for name in unpriced_models(r.usage, prices)}
    )
    costs = {id(r): cost_usd(r.usage, prices) for r in runs}
    priced = [cost for cost in costs.values() if cost is not None]
    served_priced = [cost for r in served_runs if (cost := costs[id(r)]) is not None]
    money = (
        Money(
            mean=sum(served_priced) / m if m else None,
            total=sum(priced),
        )
        if not unpriced and len(priced) == n
        else None
    )
    return CellSummary(
        model=model,
        role=role,
        scenario=scenario,
        runs=n,
        served=m,
        refused=Proportion.of(len(refused_runs), n),
        refused_kinds=dict(
            sorted(Counter(r.score.error_kind or "refused" for r in refused_runs).items())
        ),
        refused_before_any_turn=sum(1 for r in refused_runs if r.score.model_turns == 0),
        refused_after_a_turn=sum(1 for r in refused_runs if r.score.model_turns > 0),
        completed=Proportion.of(len(completed), m),
        failed=Proportion.of(ungrounded + errored, m),
        failed_ungrounded=Proportion.of(ungrounded, m),
        failed_error=Proportion.of(errored, m),
        error_kinds=dict(sorted(Counter(s.error_kind for s in served if s.error_kind).items())),
        calls=pooled_calls,
        verdict_accuracy=Proportion.of(sum(1 for s in served if s.verdict_correct), m),
        evidence_recall=Proportion.of(
            sum(s.findings_reached for s in served), sum(s.findings_required for s in served)
        ),
        missing_context_recall=Proportion.of(
            sum(s.context_named for s in served), sum(s.context_expected for s in served)
        ),
        escalation_precision=Proportion.of(correct_escalations, len(predicted)),
        escalation_recall=Proportion.of(correct_escalations, len(expected)),
        ungrounded_claim_rate=Proportion.of(ungrounded_facts, facts),
        loop_held=ungrounded_facts == 0,
        wall_clock_s=Spread(mean=sum(walls) / m, min=min(walls), max=max(walls)) if m else None,
        mean_input_tokens=_mean_tokens(served_runs, "input_tokens"),
        mean_output_tokens=_mean_tokens(served_runs, "output_tokens"),
        refused_input_tokens=sum(u.input_tokens for r in refused_runs for u in r.usage),
        refused_output_tokens=sum(u.output_tokens for r in refused_runs for u in r.usage),
        cost_usd=money,
        cost_note=("no price for " + ", ".join(unpriced)) if unpriced else None,
    )


def _mean_tokens(runs: Sequence[ScoredRun], field: str) -> float | None:
    if not runs:
        return None
    return sum(int(getattr(u, field)) for r in runs for u in r.usage) / len(runs)


def _runs(count: int) -> str:
    return f"{count} served run{'' if count == 1 else 's'}"


def render_summary(summary: Summary) -> str:
    lines = [
        f"Evaluation summary, {len(summary.cells)} cell"
        f"{'' if len(summary.cells) == 1 else 's'}, generated "
        f"{summary.generated_at.astimezone().strftime('%Y-%m-%d %H:%M %Z')}."
    ]
    if summary.fixture_digest is None:
        lines.append(
            "Campaign from before fixtures were versioned: the fixtures its runs were "
            "handed are not on record."
        )
    else:
        lines.append(f"Campaign under fixtures {summary.fixture_digest}.")
    for cell in summary.cells:
        lines.append("")
        lines.append(
            f"Cell: {cell.model}  role: {cell.role}  scenario: {cell.scenario}  runs: {cell.runs}"
        )
        kinds = ", ".join(f"{k} {v}" for k, v in cell.error_kinds.items())
        refused_kinds = ", ".join(f"{k} {v}" for k, v in cell.refused_kinds.items())
        refused = cell.refused.numerator
        calls = cell.calls
        gaps = calls.no_fixture.numerator
        other_errors = ", ".join(
            f"{k} {v}" for k, v in calls.error_kinds.items() if k != "no_fixture"
        )
        denials = ", ".join(f"{k} {v}" for k, v in calls.denial_kinds.items())
        if cell.served == 0:
            served = (
                f"0 of {cell.runs} runs; {refused} refused by the provider: "
                "THIS CELL MEASURES THE QUOTA, NOT THE MODEL"
            )
        else:
            served = (
                f"{cell.served} of {cell.runs} runs; "
                + (f"{refused} refused by the provider" if refused else "none refused")
                + "; every proportion below is over the served runs"
            )
        rows: list[tuple[str, str]] = [
            ("served", served),
            (
                "refused",
                cell.refused.render()
                + (f"  ({refused_kinds})" if refused_kinds else "")
                + (
                    f"  {cell.refused_before_any_turn} before any model turn, "
                    f"{cell.refused_after_a_turn} after one; the provider's capacity, "
                    "not the model's"
                    if refused
                    else ""
                ),
            ),
            ("completed", cell.completed.render()),
            ("failed", cell.failed.render()),
            ("  failed_ungrounded", cell.failed_ungrounded.render()),
            ("  failed_error", cell.failed_error.render() + (f"  ({kinds})" if kinds else "")),
            ("verdict accuracy", cell.verdict_accuracy.render()),
            (
                "evidence recall",
                cell.evidence_recall.render()
                + (
                    f"  {gaps} no_fixture call{'' if gaps == 1 else 's'}: a floor, see tool calls"
                    if gaps
                    else ""
                ),
            ),
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
                "tool calls",
                f"total {calls.total}  ok {calls.ok}  error {calls.error}  denied {calls.denied}",
            ),
            (
                "  no_fixture",
                calls.no_fixture.render() + f"  in {calls.runs_with_gaps} of {cell.runs} runs",
            ),
            ("  other errors", other_errors or "none"),
            ("  denied", denials or "none"),
            ("wall clock s", _wall_clock(cell)),
            ("tokens per run", _tokens(cell)),
            ("cost usd", _cost(cell)),
        ]
        lines.extend(f"  {label:<24}{value}" for label, value in rows)
    return "\n".join(lines)


def _wall_clock(cell: CellSummary) -> str:
    if cell.wall_clock_s is None:
        return "n/a, no served run"
    w = cell.wall_clock_s
    return f"mean {w.mean:.2f}  min {w.min:.2f}  max {w.max:.2f}  over {_runs(cell.served)}"


def _tokens(cell: CellSummary) -> str:
    spent = (
        f"; refused runs spent input {cell.refused_input_tokens}  "
        f"output {cell.refused_output_tokens}"
        if cell.refused_input_tokens or cell.refused_output_tokens
        else ""
    )
    if cell.mean_input_tokens is None or cell.mean_output_tokens is None:
        return "n/a, no served run" + spent
    return (
        f"input {cell.mean_input_tokens:.0f}  output {cell.mean_output_tokens:.0f}  "
        f"over {_runs(cell.served)}" + spent
    )


def _cost(cell: CellSummary) -> str:
    if cell.cost_usd is None:
        return cell.cost_note or "n/a"
    money = cell.cost_usd
    mean = (
        "mean n/a, no served run" if money.mean is None else f"mean {money.mean:.4f} per served run"
    )
    refused = ", refused included" if cell.refused.numerator else ""
    return f"{mean}  total {money.total:.4f} over all {cell.runs} runs{refused}"
