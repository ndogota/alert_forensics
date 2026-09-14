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
    With zero facts the output as a whole is the only claim, and two rules decide it:

    - A verdict other than ``inconclusive`` with no facts is an unsupported assertion:
      not grounded, rate ``1.0``.
    - An ``inconclusive`` verdict with no facts is grounded only when ``missing_context``
      is non-empty: an investigation that names what it could not establish claims
      nothing and scores ``0.0``; one that names nothing is not an investigation and
      scores ``1.0``.

    Silence therefore never scores as grounded.

    The report carries the result it describes, so it stands alone the way a trace
    does. What the consistency validator guarantees from that: the verdict and the
    missing-context count come from the result, every ``FactGrounding`` matches the
    result's fact at the same position in statement and cited ids, and every summary
    field follows from those. What it cannot guarantee without the trace: that
    ``resolved_ids``, ``source_systems`` and ``problems`` are true. Those are the
    validator's attestation; re-run :func:`validate_grounding` against the trace to
    re-verify them.
    """

    result: TriageResult
    """The result this report describes."""
    facts: list[FactGrounding]
    total_facts: int
    grounded_count: int
    ungrounded_count: int
    no_facts: bool
    """True when the result carries no observed facts at all."""
    ungrounded_claim_rate: float
    is_grounded: bool

    @property
    def verdict(self) -> Verdict:
        return self.result.verdict

    @property
    def missing_context_count(self) -> int:
        return len(self.result.missing_context)

    @property
    def grounded_facts(self) -> list[FactGrounding]:
        return [f for f in self.facts if f.grounded]

    @property
    def ungrounded_facts(self) -> list[FactGrounding]:
        return [f for f in self.facts if not f.grounded]

    @model_validator(mode="after")
    def _facts_and_summary_match_result(self) -> "GroundingReport":
        observed = self.result.observed_facts
        if len(self.facts) != len(observed):
            raise ValueError(
                f"report has {len(self.facts)} fact groundings for {len(observed)} observed facts"
            )
        for position, (grounding, fact) in enumerate(zip(self.facts, observed, strict=True)):
            if grounding.index != position:
                raise ValueError(
                    f"fact grounding at position {position} has index {grounding.index}"
                )
            if grounding.statement != fact.statement:
                raise ValueError(f"fact grounding {position} does not match the result's statement")
            if grounding.evidence_ids != list(dict.fromkeys(fact.evidence)):
                raise ValueError(f"fact grounding {position} does not match the result's evidence")
        expected = _summarise(self.result, self.facts)
        actual = {name: getattr(self, name) for name in expected}
        if actual != expected:
            mismatched = sorted(name for name in expected if actual[name] != expected[name])
            raise ValueError(f"report summary does not match its facts: {mismatched}")
        return self


def _summarise(result: TriageResult, facts: list[FactGrounding]) -> dict[str, object]:
    total = len(facts)
    grounded_count = sum(1 for f in facts if f.grounded)
    ungrounded_count = total - grounded_count
    no_facts = total == 0
    if no_facts:
        honest_silence = result.verdict is Verdict.inconclusive and bool(result.missing_context)
        is_grounded = honest_silence
        rate = 0.0 if honest_silence else 1.0
    else:
        is_grounded = ungrounded_count == 0
        rate = ungrounded_count / total
    return {
        "total_facts": total,
        "grounded_count": grounded_count,
        "ungrounded_count": ungrounded_count,
        "no_facts": no_facts,
        "ungrounded_claim_rate": rate,
        "is_grounded": is_grounded,
    }


def validate_grounding(result: TriageResult, trace: InvestigationTrace) -> GroundingReport:
    """Resolve every observed fact's evidence against the trace and report.

    A fact is grounded only when every distinct id it cites resolves to a record whose
    outcome is ``ok``. A fact may cite records from several source systems; that is a
    correlation, not a defect. Assumptions and missing context are exempt: they carry no
    evidence by design. A result with no facts is grounded only when the verdict is
    ``inconclusive`` and missing context is named: silence must not score.
    """
    index = {record.tool_call_id: record for record in trace.records}
    facts = [_ground_fact(i, fact, index) for i, fact in enumerate(result.observed_facts)]
    summary = _summarise(result, facts)
    return GroundingReport.model_validate({"result": result, "facts": facts, **summary})


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
