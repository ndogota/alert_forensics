"""``propose_alert_disposition``: the one write action, and it writes nothing.

It records a proposed verdict and recommended action for a human to accept or reject.
It has no upstream: the shape is the project's own, the source system is ``human``, and
the adapter echoes the proposal with a timestamp. The human-in-the-loop middleware
interrupts on it before it runs; the scope check decides whether it may run at all; the
ordering rules say when: after at least one call returned evidence, and alone in its turn.
"""

from typing import Literal

from pydantic import Field

from alert_forensics.contracts import SourceSystem, Verdict
from alert_forensics.tools.adapter import (
    LiveContract,
    ToolDefinition,
    ToolRequest,
    ToolResponse,
    ToolView,
)

NOTHING_WRITTEN = (
    "Recorded for analyst review. Nothing was written to the alert, the incident or any "
    "case system; the analyst decides."
)


class ProposeDispositionRequest(ToolRequest):
    verdict: Verdict = Field(description="The verdict you propose for this alert.")
    recommended_action: str = Field(
        min_length=1, description="What the SOC should do next, in one or two sentences."
    )
    escalate: bool = Field(description="Whether the alert should go to the next tier.")
    summary: str = Field(
        min_length=1,
        description="One paragraph for the analyst: what was observed and why it leads here.",
    )


class ProposeDispositionResponse(ToolResponse):
    status: Literal["proposed"]
    verdict: Verdict
    recommended_action: str
    escalate: bool
    summary: str
    proposed_at: str


class ProposeDispositionView(ToolView):
    status: Literal["proposed"]
    verdict: Verdict
    recommended_action: str
    escalate: bool
    proposed_at: str
    note: str


def _project(
    response: ProposeDispositionResponse, request: ProposeDispositionRequest | None
) -> ProposeDispositionView:
    return ProposeDispositionView(
        status=response.status,
        verdict=response.verdict,
        recommended_action=response.recommended_action,
        escalate=response.escalate,
        proposed_at=response.proposed_at,
        note=NOTHING_WRITTEN,
    )


PROPOSE_ALERT_DISPOSITION = ToolDefinition(
    name="propose_alert_disposition",
    description=(
        "Propose a disposition for the alert to the analyst: a verdict, a recommended "
        "action, whether to escalate, and a one-paragraph summary. This writes nothing; "
        "the analyst accepts or rejects the proposal. Call it once, after the investigation "
        "and before your final answer."
    ),
    source_system=SourceSystem.human,
    required_scope="alerts:write",
    request_model=ProposeDispositionRequest,
    response_model=ProposeDispositionResponse,
    view_model=ProposeDispositionView,
    projector=_project,
    needs_evidence=True,
    alone_in_turn=True,
    live=LiveContract(
        status="local",
        system="the analyst",
        endpoint="none; the proposal is recorded in the run artifact",
        auth="none",
        permission="alerts:write, the project's own scope, held by analyst and not by tier1",
        notes=(
            "Interrupts the graph before it runs. A tenant that wants the proposal to reach "
            "a case system writes an adapter here; the shape the model sees does not change."
        ),
    ),
)
