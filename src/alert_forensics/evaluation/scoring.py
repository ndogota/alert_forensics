"""One run scored against its ground truth.

Deterministic and legible: a required finding is matched by the tool a fact cites and
the tokens its statement contains, and a miss names the tokens the closest candidate
lacked. No model is asked anything. A failed run scores zero on every metric.
"""

from pydantic import Field

from alert_forensics.artifact import RunArtifact
from alert_forensics.contracts import InvestigationTrace, MissingContext, RunOutcome, Verdict
from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.evaluation.truth import (
    ExpectedContext,
    GroundTruth,
    RequiredFinding,
    Token,
)
from alert_forensics.grounding import FactGrounding, GroundingReport


def normalise(text: str) -> str:
    return " ".join(text.split()).casefold()


def _present(text: str, token: Token) -> bool:
    if isinstance(token, str):
        return normalise(token) in text
    return any(normalise(alternative) in text for alternative in token)


def contains_tokens(text: str, tokens: list[Token]) -> list[Token]:
    """The tokens ``text`` lacks, in order; empty when every token is present. A token
    that is a list of alternatives is present when any one of them is, and is reported
    whole when none is."""
    normalised = normalise(text)
    return [token for token in tokens if not _present(normalised, token)]


class FindingMatch(ContractModel):
    name: NonEmptyStr
    reached: bool
    fact_index: int | None
    """The first grounded fact that carried the finding."""
    cited_tool: str | None
    """The tool, among the finding's, that the carrying fact cited."""
    candidates: StrictNonNegativeInt
    """Grounded facts that cited one of the finding's tools, whatever they said."""
    missed_tokens: list[Token] = Field(default_factory=list)
    """On a miss: the tokens lacked by the candidate that lacked fewest, or every token
    when there was no candidate."""


class ContextMatch(ContractModel):
    name: NonEmptyStr
    named: bool
    entry_index: int | None


class RunScore(ContractModel):
    """The score of one run. Fully derived from the artifact and the ground truth."""

    scenario: NonEmptyStr
    outcome: RunOutcome
    verdict_expected: Verdict
    verdict_observed: Verdict | None
    """The result's verdict when there was a result, for inspection; a failed run's
    verdict is never correct, whatever it says."""
    verdict_correct: bool
    findings: list[FindingMatch]
    findings_reached: StrictNonNegativeInt
    findings_required: StrictNonNegativeInt
    context: list[ContextMatch]
    context_named: StrictNonNegativeInt
    context_expected: StrictNonNegativeInt
    escalate_expected: bool
    escalate_predicted: bool | None
    """None on a failed run: it predicted nothing."""
    escalation_correct: bool
    total_facts: StrictNonNegativeInt
    ungrounded_facts: StrictNonNegativeInt
    error_kind: str | None


def score_run(artifact: RunArtifact, truth: GroundTruth) -> RunScore:
    if artifact.trace.alert.id != truth.alert_id:
        raise ValueError(
            f"the artifact is a run of alert {artifact.trace.alert.id!r}, and the ground "
            f"truth is for alert {truth.alert_id!r}"
        )
    completed = artifact.outcome is RunOutcome.completed
    report = artifact.report
    result = report.result if report is not None else None
    if completed and report is not None and result is not None:
        findings = [_match_finding(f, report, artifact.trace) for f in truth.required_findings]
        context = [_match_context(c, result.missing_context) for c in truth.missing_context]
        verdict: Verdict | None = result.verdict
        predicted: bool | None = result.escalate
    else:
        findings = [_unreached(f) for f in truth.required_findings]
        context = [
            ContextMatch(name=c.name, named=False, entry_index=None) for c in truth.missing_context
        ]
        verdict = result.verdict if result is not None else None
        predicted = None
    return RunScore(
        scenario=truth.scenario,
        outcome=artifact.outcome,
        verdict_expected=truth.verdict,
        verdict_observed=verdict,
        verdict_correct=completed and verdict is truth.verdict,
        findings=findings,
        findings_reached=sum(1 for f in findings if f.reached),
        findings_required=len(findings),
        context=context,
        context_named=sum(1 for c in context if c.named),
        context_expected=len(context),
        escalate_expected=truth.escalate,
        escalate_predicted=predicted,
        escalation_correct=completed and predicted == truth.escalate,
        total_facts=report.total_facts if report is not None else 0,
        ungrounded_facts=report.ungrounded_count if report is not None else 0,
        error_kind=artifact.error.kind if artifact.error is not None else None,
    )


def _unreached(finding: RequiredFinding) -> FindingMatch:
    return FindingMatch(
        name=finding.name,
        reached=False,
        fact_index=None,
        cited_tool=None,
        candidates=0,
        missed_tokens=list(finding.tokens),
    )


def _cited_tool(fact: FactGrounding, trace: InvestigationTrace, tools: list[str]) -> str | None:
    """The first of ``tools`` among the calls the fact resolved to."""
    for evidence_id in fact.resolved_ids:
        record = trace.find(evidence_id)
        if record is not None and record.tool_name in tools:
            return record.tool_name
    return None


def _match_finding(
    finding: RequiredFinding, report: GroundingReport, trace: InvestigationTrace
) -> FindingMatch:
    candidates = 0
    closest: list[Token] | None = None
    for fact in report.facts:
        if not fact.grounded:
            continue
        tool = _cited_tool(fact, trace, finding.tools)
        if tool is None:
            continue
        candidates += 1
        missed = contains_tokens(fact.statement, finding.tokens)
        if not missed:
            return FindingMatch(
                name=finding.name,
                reached=True,
                fact_index=fact.index,
                cited_tool=tool,
                candidates=candidates,
                missed_tokens=[],
            )
        if closest is None or len(missed) < len(closest):
            closest = missed
    return FindingMatch(
        name=finding.name,
        reached=False,
        fact_index=None,
        cited_tool=None,
        candidates=candidates,
        missed_tokens=list(finding.tokens) if closest is None else closest,
    )


def _match_context(expected: ExpectedContext, entries: list[MissingContext]) -> ContextMatch:
    for index, entry in enumerate(entries):
        text = " ".join((entry.what, entry.why_it_matters, entry.how_to_obtain))
        if not contains_tokens(text, expected.tokens):
            return ContextMatch(name=expected.name, named=True, entry_index=index)
    return ContextMatch(name=expected.name, named=False, entry_index=None)
