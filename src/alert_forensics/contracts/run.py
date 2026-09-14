"""The outcome of a run and the human decisions taken during it.

These are contracts because the evaluation reads them: a failed run is a first-class
number, and a decision on a proposal is part of the record of an investigation.
"""

from enum import StrEnum
from typing import Literal

from pydantic import JsonValue

from alert_forensics.contracts._base import ContractModel, NonEmptyStr

AdapterKind = Literal["fixture", "live", "local"]


class RunOutcome(StrEnum):
    completed = "completed"
    """The loop ended with a grounded result."""
    failed_ungrounded = "failed_ungrounded"
    """The loop ended and the result is still ungrounded. Never laundered into a verdict."""
    failed_error = "failed_error"
    """No result was produced: model error, unparseable output, budget."""


class RunError(ContractModel):
    kind: NonEmptyStr
    """The exception's class name, or ``budget`` for the recursion limit, or
    ``no_result`` when the model ended without a structured result."""
    message: str


class DispositionDecision(StrEnum):
    accepted = "accepted"
    rejected = "rejected"


class HumanDecision(ContractModel):
    """What the analyst did with one proposal, recorded with the proposal it answered."""

    tool_call_id: NonEmptyStr
    proposal: dict[str, JsonValue]
    """The proposal's arguments as the model wrote them, before any validation."""
    decision: DispositionDecision
    reason: str | None = None
