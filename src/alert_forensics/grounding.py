"""The grounding validator.

A claim that cannot be attached to a real, successful tool call is not a fact. This module
resolves every evidence id an observed fact cites against the investigation trace and
reports what it found. It takes no model, performs no IO, and never repairs the result.
"""

from typing import Literal

from pydantic import model_validator

from alert_forensics.contracts._base import ContractModel
from alert_forensics.contracts.trace import (
    InvestigationTrace,
    SourceSystem,
    ToolCallRecord,
    ToolOutcome,
)
from alert_forensics.contracts.triage import ObservedFact, TriageResult, Verdict

GroundingProblemKind = Literal["unknown_id", "cites_unsuccessful_call"]


class GroundingProblem(ContractModel):
    evidence_id: str
    kind: GroundingProblemKind
    detail: str


class FactGrounding(ContractModel):
    """The grounding outcome for one observed fact."""

    index: int
    statement: str
    evidence_ids: list[str]
    """Cited ids, deduplicated, first occurrence order."""
    resolved_ids: list[str]
    """Cited ids that resolve to a record in the trace, whatever its outcome."""
    source_systems: list[SourceSystem]
    """Systems the resolved records read from, derived from the trace, never from the model.
    A fact may legitimately correlate several systems."""
    problems: list[GroundingProblem]
    grounded: bool


class GroundingReport(ContractModel):
    """The outcome of grounding one result against one trace.

    ``ungrounded_claim_rate`` is ungrounded facts over total facts when there are facts.
    With zero facts the verdict itself is the only claim: it is ``1.0`` when the verdict
    asserts something (anything but ``inconclusive``), because an unsupported verdict is
    one claim, wholly ungrounded; it is ``0.0`` for ``inconclusive``, which claims nothing.
    Silence therefore never scores as grounded.
    """

    verdict: Verdict
    facts: list[FactGrounding]
    total_facts: int
    grounded_count: int
    ungrounded_count: int
    no_facts: bool
    """True when the result carries no observed facts at all."""
    ungrounded_claim_rate: float
    is_grounded: bool

    @property
    def grounded_facts(self) -> list[FactGrounding]:
        return [f for f in self.facts if f.grounded]

    @property
    def ungrounded_facts(self) -> list[FactGrounding]:
        return [f for f in self.facts if not f.grounded]

    @model_validator(mode="after")
    def _summary_matches_facts(self) -> "GroundingReport":
        expected = _summarise(self.verdict, self.facts)
        actual = {name: getattr(self, name) for name in expected}
        if actual != expected:
            mismatched = sorted(name for name in expected if actual[name] != expected[name])
            raise ValueError(f"report summary does not match its facts: {mismatched}")
        return self


def _summarise(verdict: Verdict, facts: list[FactGrounding]) -> dict[str, object]:
    total = len(facts)
    grounded_count = sum(1 for f in facts if f.grounded)
    ungrounded_count = total - grounded_count
    no_facts = total == 0
    silent_assertion = no_facts and verdict is not Verdict.inconclusive
    rate = ungrounded_count / total if total else (1.0 if silent_assertion else 0.0)
    return {
        "total_facts": total,
        "grounded_count": grounded_count,
        "ungrounded_count": ungrounded_count,
        "no_facts": no_facts,
        "ungrounded_claim_rate": rate,
        "is_grounded": ungrounded_count == 0 and not silent_assertion,
    }


def validate_grounding(result: TriageResult, trace: InvestigationTrace) -> GroundingReport:
    """Resolve every observed fact's evidence against the trace and report.

    A fact is grounded only when every distinct id it cites resolves to a record whose
    outcome is ``ok``. A fact may cite records from several source systems; that is a
    correlation, not a defect. Assumptions and missing context are exempt: they carry no
    evidence by design. A result with no facts and a verdict other than ``inconclusive``
    is not grounded: silence must not score.
    """
    index = {record.tool_call_id: record for record in trace.records}
    facts = [_ground_fact(i, fact, index) for i, fact in enumerate(result.observed_facts)]
    summary = _summarise(result.verdict, facts)
    return GroundingReport.model_validate({"verdict": result.verdict, "facts": facts, **summary})


def attach_source_systems(result: TriageResult, report: GroundingReport) -> TriageResult:
    """Return a copy of ``result`` whose facts carry the source systems the report derived.

    This is the only way ``ObservedFact.source_systems`` is meant to be populated: from the
    trace, deterministically, after grounding. The field is hidden from the model-facing
    JSON schema and ignored by :func:`validate_grounding`.
    """
    if len(report.facts) != len(result.observed_facts):
        raise ValueError("report and result do not describe the same facts")
    facts = [
        fact.model_copy(update={"source_systems": list(grounding.source_systems)})
        for fact, grounding in zip(result.observed_facts, report.facts, strict=True)
    ]
    return result.model_copy(update={"observed_facts": facts})


def _ground_fact(
    position: int, fact: ObservedFact, index: dict[str, ToolCallRecord]
) -> FactGrounding:
    evidence_ids = list(dict.fromkeys(fact.evidence))
    resolved_ids: list[str] = []
    source_systems: list[SourceSystem] = []
    problems: list[GroundingProblem] = []
    for evidence_id in evidence_ids:
        record = index.get(evidence_id)
        if record is None:
            problems.append(
                GroundingProblem(
                    evidence_id=evidence_id,
                    kind="unknown_id",
                    detail="no tool call with this id exists in the trace",
                )
            )
            continue
        resolved_ids.append(evidence_id)
        if record.source_system not in source_systems:
            source_systems.append(record.source_system)
        if record.outcome is not ToolOutcome.ok:
            problems.append(
                GroundingProblem(
                    evidence_id=evidence_id,
                    kind="cites_unsuccessful_call",
                    detail=(
                        f"tool {record.tool_name!r} ended with outcome "
                        f"{record.outcome.value} and returned no data"
                    ),
                )
            )
    return FactGrounding(
        index=position,
        statement=fact.statement,
        evidence_ids=evidence_ids,
        resolved_ids=resolved_ids,
        source_systems=source_systems,
        problems=problems,
        grounded=not problems,
    )
