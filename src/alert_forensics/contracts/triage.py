"""Triage output contract. Three separate lists: facts, assumptions, missing context.

Only observed facts carry evidence. An assumption or a missing-context entry is, by
definition, not attached to a tool call and is exempt from grounding.
"""

from enum import StrEnum
from typing import Annotated

from pydantic import Field
from pydantic.json_schema import SkipJsonSchema

from alert_forensics.contracts._base import ContractModel, NonEmptyStr
from alert_forensics.contracts.alert import MitreTechniqueId
from alert_forensics.contracts.trace import SourceSystem


class Verdict(StrEnum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign_true_positive = "benign_true_positive"
    inconclusive = "inconclusive"


class ObservedFact(ContractModel):
    """A claim that rests on at least one tool call. Duplicate ids are tolerated here and
    deduplicated by the grounding validator, so the report reflects what was emitted."""

    statement: NonEmptyStr
    evidence: Annotated[list[NonEmptyStr], Field(min_length=1)]
    """Tool call ids this fact rests on. A fact may cite several source systems."""
    source_systems: SkipJsonSchema[list[SourceSystem]] = Field(default_factory=list)
    """Derived from the trace by ``attach_source_systems`` after grounding. Excluded from the
    model-facing JSON schema and ignored by the validator: the model never declares it."""


class Assumption(ContractModel):
    statement: NonEmptyStr
    why_unverified: NonEmptyStr


class MissingContext(ContractModel):
    what: NonEmptyStr
    why_it_matters: NonEmptyStr
    how_to_obtain: NonEmptyStr


class TriageResult(ContractModel):
    verdict: Verdict
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    mitre_techniques: list[MitreTechniqueId] = Field(default_factory=list)
    observed_facts: list[ObservedFact] = Field(default_factory=list)
    assumptions: list[Assumption] = Field(default_factory=list)
    missing_context: list[MissingContext] = Field(default_factory=list)
    recommended_action: NonEmptyStr
    escalate: bool
