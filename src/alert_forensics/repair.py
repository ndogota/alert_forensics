"""The correction pass: what the second model call receives and what it may return.

The instruction is built from the grounding report and the trace: the offending facts by
index, each with the statement, the offending id and the problem kind; and the calls
present in the trace, each with the tool it called, the arguments the model itself wrote,
and the outcome. Never a response, never a grounded fact. The repairs come back by index
and are applied here, deterministically, to the offending facts only.
"""

from typing import Literal

from pydantic import Field, JsonValue, model_validator

from alert_forensics.contracts import (
    Assumption,
    InvestigationTrace,
    ObservedFact,
    ToolOutcome,
    TriageResult,
)
from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.grounding import GroundingProblemKind, GroundingReport


class PresentCall(ContractModel):
    """A call the trace holds, without its response."""

    tool_call_id: NonEmptyStr
    tool_name: NonEmptyStr
    arguments: dict[str, JsonValue]
    outcome: ToolOutcome


class OffendingCitation(ContractModel):
    """One bad citation on one fact. A fact with two bad ids appears twice."""

    index: StrictNonNegativeInt
    statement: NonEmptyStr
    evidence_id: NonEmptyStr
    problem: GroundingProblemKind


class RepairInstruction(ContractModel):
    offending: list[OffendingCitation]
    present_calls: list[PresentCall]


class CitationRepair(ContractModel):
    """Re-cite a fact from the present calls, or withdraw it to the assumptions."""

    index: StrictNonNegativeInt = Field(description="Index of the offending fact.")
    action: Literal["recite", "withdraw"]
    evidence: list[NonEmptyStr] = Field(
        default_factory=list,
        description="For recite: tool_call_ids from the present calls that support the fact.",
    )
    why_unverified: str | None = Field(
        default=None, description="For withdraw: why the fact could not be verified."
    )

    @model_validator(mode="after")
    def _shape_follows_action(self) -> "CitationRepair":
        if self.action == "recite":
            if not self.evidence:
                raise ValueError("a recite repair names at least one tool_call_id")
            if self.why_unverified is not None:
                raise ValueError("a recite repair carries no why_unverified")
        else:
            if not (self.why_unverified or "").strip():
                raise ValueError("a withdraw repair says why the fact could not be verified")
            if self.evidence:
                raise ValueError("a withdraw repair cites nothing")
        return self


class CitationRepairs(ContractModel):
    """The second pass's whole output. One entry per offending fact it chose to repair."""

    repairs: list[CitationRepair] = Field(default_factory=list)


def build_repair_instruction(
    report: GroundingReport, trace: InvestigationTrace
) -> RepairInstruction:
    offending = [
        OffendingCitation(
            index=fact.index,
            statement=fact.statement,
            evidence_id=problem.evidence_id,
            problem=problem.kind,
        )
        for fact in report.facts
        if not fact.grounded
        for problem in fact.problems
    ]
    present = [
        PresentCall(
            tool_call_id=record.tool_call_id,
            tool_name=record.tool_name,
            arguments=record.arguments,
            outcome=record.outcome,
        )
        for record in trace.records
    ]
    return RepairInstruction(offending=offending, present_calls=present)


def apply_repairs(
    result: TriageResult, report: GroundingReport, repairs: CitationRepairs
) -> TriageResult:
    """Apply repairs to the offending facts of ``result`` as ``report`` identifies them.

    A repair naming a grounded fact, or a fact that does not exist, is ignored. An
    offending fact with no repair stays as it was. Nothing but ``observed_facts`` and
    ``assumptions`` changes.
    """
    offending = {fact.index for fact in report.facts if not fact.grounded}
    by_index: dict[int, CitationRepair] = {}
    for candidate in repairs.repairs:
        if candidate.index in offending and candidate.index not in by_index:
            by_index[candidate.index] = candidate
    facts: list[ObservedFact] = []
    withdrawn: list[Assumption] = []
    for index, fact in enumerate(result.observed_facts):
        repair = by_index.get(index)
        if repair is None:
            facts.append(fact)
        elif repair.action == "recite":
            facts.append(ObservedFact(statement=fact.statement, evidence=repair.evidence))
        else:
            withdrawn.append(
                Assumption(statement=fact.statement, why_unverified=str(repair.why_unverified))
            )
    return result.model_copy(
        update={"observed_facts": facts, "assumptions": [*result.assumptions, *withdrawn]}
    )
