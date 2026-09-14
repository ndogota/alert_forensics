"""The ordering rules a definition may declare, and the check that produces a denial.

The write action comes after evidence and comes alone. Both rules are declared on the
definition and enforced here, in the pipeline, not in the prompt: a prompt is advice,
a denial is a fact the model reads and the journal keeps.
"""

from collections.abc import Sequence
from typing import Any, Literal

from alert_forensics.contracts import ToolCallRecord, ToolOutcome
from alert_forensics.contracts._base import ContractModel
from alert_forensics.tools.adapter import ToolDefinition
from alert_forensics.tools.scope import Principal

OrderRule = Literal["needs_evidence", "alone_in_turn"]


class OrderDenial(ContractModel):
    """What the model receives when a call breaks an ordering rule. The same shape as a
    scope denial, with the rule in place of the scope."""

    error: Literal["order_denied"] = "order_denied"
    tool: str
    rule: OrderRule
    caller: str
    role: str
    message: str


def has_evidence(records: Sequence[ToolCallRecord]) -> bool:
    """At least one call in the journal returned data."""
    return any(r.outcome is ToolOutcome.ok for r in records)


def offerable(definition: ToolDefinition[Any, Any, Any], records: Sequence[ToolCallRecord]) -> bool:
    """Whether the tool is offered to the model at this point of the run."""
    return not definition.needs_evidence or has_evidence(records)


def check_order(
    principal: Principal,
    definition: ToolDefinition[Any, Any, Any],
    records: Sequence[ToolCallRecord],
    turn_siblings: Sequence[str],
) -> OrderDenial | None:
    """Return a denial when the call breaks a rule the definition declares, else None.

    ``turn_siblings`` are the names of the other calls the model emitted in the same
    turn, passed by the caller: a call may run before its siblings are journalled.
    """
    if definition.needs_evidence and not has_evidence(records):
        return _denial(
            principal,
            definition,
            "needs_evidence",
            f"{definition.name} is not available until at least one tool call has returned "
            "with outcome ok. Gather evidence first, then propose.",
        )
    if definition.alone_in_turn and turn_siblings:
        others = ", ".join(sorted(set(turn_siblings)))
        return _denial(
            principal,
            definition,
            "alone_in_turn",
            f"{definition.name} must be the only tool call in its turn; this turn also "
            f"called {others}. Wait for their results, then propose on its own.",
        )
    return None


def _denial(
    principal: Principal, definition: ToolDefinition[Any, Any, Any], rule: OrderRule, message: str
) -> OrderDenial:
    return OrderDenial(
        tool=definition.name,
        rule=rule,
        caller=principal.name,
        role=principal.role.name,
        message=message,
    )
