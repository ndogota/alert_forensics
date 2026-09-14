"""The run artifact: one investigation, its outcome, its trace and its report.

The outcome lives here beside the trace and the report, and the consistency between them
is validated: ``completed`` means a grounded report, ``failed_ungrounded`` an ungrounded
one, ``failed_error`` an error and no report. A correction means two passes.
"""

from pydantic import Field, model_validator

from alert_forensics.contracts import (
    AdapterKind,
    HumanDecision,
    InvestigationTrace,
    ModelLimits,
    RunError,
    RunOutcome,
    TriageResult,
)
from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.grounding import GroundingReport
from alert_forensics.repair import CitationRepairs, RepairInstruction


class CorrectionRecord(ContractModel):
    """What the correction pass was sent, what came back, and what it was repairing."""

    instruction: RepairInstruction
    repairs: CitationRepairs
    report_before: GroundingReport


class RunArtifact(ContractModel):
    investigation_id: NonEmptyStr
    outcome: RunOutcome
    model: NonEmptyStr
    """The provider:model string the run was started with."""
    model_limits: ModelLimits | None = None
    """The timeout and retry bound the model client ran under. None for the scripted
    client, which makes no network call."""
    role: NonEmptyStr
    adapters: dict[str, AdapterKind]
    """Which kind of adapter served each tool offered to the model."""
    trace: InvestigationTrace
    report: GroundingReport | None
    """The grounding report of the final result. It carries the result."""
    passes: StrictNonNegativeInt
    """Model passes that produced a result: 0 on failed_error, else 1 plus the corrections."""
    corrections: list[CorrectionRecord] = Field(default_factory=list)
    """One record per correction pass, in order. Bounded by ``max_corrections``."""
    decisions: list[HumanDecision] = Field(default_factory=list)
    error: RunError | None = None
    """The error on ``failed_error``; on ``failed_ungrounded`` the correction pass's own
    failure when it had one; never on ``completed``."""
    raw_store: NonEmptyStr
    """Directory, relative to the artifact, the trace's raw_response_refs resolve under."""

    @property
    def result(self) -> TriageResult | None:
        return self.report.result if self.report is not None else None

    @property
    def correction(self) -> CorrectionRecord | None:
        """The last correction pass, or None."""
        return self.corrections[-1] if self.corrections else None

    @model_validator(mode="after")
    def _outcome_matches_report(self) -> "RunArtifact":
        if self.outcome is RunOutcome.completed:
            if self.report is None or not self.report.is_grounded:
                raise ValueError("a completed run carries a grounded report")
            if self.error is not None:
                raise ValueError("a completed run carries no error")
        elif self.outcome is RunOutcome.failed_ungrounded:
            if self.report is None or self.report.is_grounded:
                raise ValueError("a failed_ungrounded run carries an ungrounded report")
        else:
            if self.error is None:
                raise ValueError("a failed_error run carries its error")
            if self.report is not None:
                raise ValueError("a failed_error run produced no result, so no report")
        if (self.report is None) != (self.passes == 0):
            raise ValueError("passes is zero exactly when no result was produced")
        if self.passes and self.passes != 1 + len(self.corrections):
            raise ValueError("passes is one plus the number of corrections")
        if not self.passes and self.corrections:
            raise ValueError("a run that produced no result made no correction")
        return self
