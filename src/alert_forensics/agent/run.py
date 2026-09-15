"""Run one investigation end to end and return the artifact, whatever happened."""

import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from langchain_core.exceptions import ModelRateLimitError
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.errors import GraphRecursionError
from langgraph.types import Command, StateSnapshot
from pydantic import JsonValue

from alert_forensics.agent.graph import GATED_TOOL, TriageGraph, build_triage_graph
from alert_forensics.agent.prompts import alert_message
from alert_forensics.agent.strategy import output_binding
from alert_forensics.artifact import CorrectionRecord, RunArtifact
from alert_forensics.contracts import PROVIDER_REFUSALS as PROVIDER_REFUSALS
from alert_forensics.contracts import (
    Alert,
    Assumption,
    DispositionDecision,
    HumanDecision,
    InputTokenDetails,
    InvestigationTrace,
    MissingContext,
    ModelLimits,
    ModelUsageRecord,
    ObservedFact,
    OutputTokenDetails,
    RunError,
    RunOutcome,
    SourceSystem,
    ToolCallRecord,
    ToolOutcome,
    TriageResult,
    Verdict,
)
from alert_forensics.contracts._base import ContractModel
from alert_forensics.grounding import FactGrounding, GroundingProblem, GroundingReport
from alert_forensics.repair import (
    CitationRepair,
    CitationRepairs,
    OffendingCitation,
    PresentCall,
    RepairInstruction,
)
from alert_forensics.tools.fixtures import FixtureAdapter
from alert_forensics.tools.runner import AnyAdapter, ToolRunner
from alert_forensics.tools.scope import Principal
from alert_forensics.tools.store import RawResponseStore

CHECKPOINT_TYPES: tuple[type, ...] = (
    TriageResult,
    Verdict,
    ObservedFact,
    Assumption,
    MissingContext,
    GroundingReport,
    FactGrounding,
    GroundingProblem,
    SourceSystem,
    ToolOutcome,
    RunOutcome,
    RunError,
    CorrectionRecord,
    RepairInstruction,
    OffendingCitation,
    PresentCall,
    CitationRepairs,
    CitationRepair,
)
"""The project's own types that may live in a checkpoint. The serializer deserialises
these and LangGraph's built-ins, and refuses anything else: a checkpoint is data, and
data does not get to name a class."""


def checkpointer() -> InMemorySaver:
    return InMemorySaver(serde=JsonPlusSerializer(allowed_msgpack_modules=CHECKPOINT_TYPES))


class AnalystDecision(ContractModel):
    accept: bool
    reason: str | None = None


DecideFn = Callable[[dict[str, JsonValue]], AnalystDecision]
"""Given the proposal's arguments as the model wrote them, the analyst's decision."""

_RATE_LIMIT_STATUS = {429}
_OVERLOADED_STATUS = {503, 529}
_RATE_LIMIT_TEXT = re.compile(r"\b429\b|resource_exhausted|rate.?limit|quota", re.IGNORECASE)
_OVERLOADED_TEXT = re.compile(r"\b503\b|\b529\b|unavailable|overloaded", re.IGNORECASE)


def run_error(exc: BaseException) -> RunError:
    """The error a raised exception becomes on the artifact.

    A provider refusal is named as such, ``rate_limit`` or ``overloaded``, rather than
    by its class: LangChain's error class first, then the status code the exception
    carries, then the message, so a client that does not map onto LangChain's classes
    is still named. Anything else keeps its class name.
    """
    message = str(exc)
    return RunError(kind=_error_kind(exc, message), message=message)


def _error_kind(exc: BaseException, message: str) -> str:
    if isinstance(exc, ModelRateLimitError):
        return "rate_limit"
    status = _status_code(exc)
    if status in _RATE_LIMIT_STATUS:
        return "rate_limit"
    if status in _OVERLOADED_STATUS:
        return "overloaded"
    if status is None:
        if _RATE_LIMIT_TEXT.search(message):
            return "rate_limit"
        if _OVERLOADED_TEXT.search(message):
            return "overloaded"
    return type(exc).__name__


def _status_code(exc: BaseException) -> int | None:
    """The HTTP status an SDK exception carries: ``status_code`` on the Anthropic and
    OpenAI clients, ``code`` on Google's."""
    for name in ("status_code", "code"):
        value = getattr(exc, name, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def run_triage(
    *,
    alert: Alert,
    model: BaseChatModel,
    model_id: str,
    principal: Principal,
    adapters: Iterable[AnyAdapter],
    store: RawResponseStore,
    raw_store: str,
    decide: DecideFn,
    investigation_id: str | None = None,
    max_corrections: int = 1,
    recursion_limit: int = 50,
    clock: Callable[[], datetime] | None = None,
    model_limits: ModelLimits | None = None,
    on_tool_call: Callable[[ToolCallRecord], None] | None = None,
) -> RunArtifact:
    clock = clock or (lambda: datetime.now(UTC))
    started_at = clock()
    investigation_id = investigation_id or f"inv-{uuid4().hex[:12]}"
    runner = ToolRunner(
        adapters=adapters,
        principal=principal,
        store=store,
        investigation_id=investigation_id,
        clock=clock,
        on_record=on_tool_call,
    )
    graph = build_triage_graph(
        model=model,
        runner=runner,
        alert=alert,
        started_at=started_at,
        max_corrections=max_corrections,
        checkpointer=checkpointer(),
    )
    config: RunnableConfig = {
        "configurable": {"thread_id": investigation_id},
        "recursion_limit": recursion_limit,
        # One turn's tool calls run one at a time, in the order the model emitted them,
        # so the journal order is the model's order and a run is deterministic.
        "max_concurrency": 1,
    }
    decisions: list[HumanDecision] = []
    error: RunError | None = None
    state: dict[str, Any] = {}
    try:
        state = graph.invoke({"messages": [HumanMessage(alert_message(alert))]}, config)
        while state.get("__interrupt__"):
            request = state["__interrupt__"][0].value
            resume = _decide(request, _pending_proposal_ids(graph, config), decide, decisions)
            state = graph.invoke(Command(resume={"decisions": resume}), config)
    except GraphRecursionError as exc:
        error = RunError(kind="budget", message=str(exc))
    except Exception as exc:
        error = run_error(exc)

    snapshot = graph.get_state(config).values
    messages = _all_messages(graph, config) or list(state.get("messages") or [])
    trace = InvestigationTrace(
        investigation_id=investigation_id,
        alert=alert,
        started_at=started_at,
        records=list(runner.records),
        usage=usage_records(messages, model_id),
    )
    report = snapshot.get("report")
    corrections = list(snapshot.get("corrections", []))
    passes = int(snapshot.get("passes", 0))
    if error is None:
        error = snapshot.get("error") or state.get("error")
        outcome = state.get("outcome") or RunOutcome.failed_error
    elif report is not None and not report.is_grounded and passes >= 1:
        # The correction pass itself failed: the first pass's result stands, ungrounded.
        outcome = RunOutcome.failed_ungrounded
    else:
        outcome = RunOutcome.failed_error
    if outcome is RunOutcome.failed_error:
        report, passes, corrections = None, 0, []
    return RunArtifact(
        investigation_id=investigation_id,
        outcome=outcome,
        model=model_id,
        model_limits=model_limits,
        output_binding=output_binding(model),
        role=principal.role.name,
        adapters={name: adapter.kind for name, adapter in runner.adapters.items()},
        fixture_labels=sorted(
            set().union(
                *(a.in_view for a in runner.adapters.values() if isinstance(a, FixtureAdapter))
            )
        ),
        trace=trace,
        report=report,
        passes=passes,
        corrections=corrections,
        decisions=decisions,
        error=error,
        raw_store=raw_store,
    )


def _all_messages(graph: TriageGraph, config: RunnableConfig) -> list[AnyMessage]:
    """Every message of the thread, including the investigate subgraph's own when it has
    not returned: after an interrupt, or after it raised."""
    snapshot = graph.get_state(config, subgraphs=True)
    messages: list[AnyMessage] = list(snapshot.values.get("messages", []))
    for task in snapshot.tasks:
        inner = task.state
        if not isinstance(inner, StateSnapshot):
            continue
        inner_messages: list[AnyMessage] = list(inner.values.get("messages", []))
        if len(inner_messages) > len(messages):
            messages = inner_messages
    return messages


def _pending_proposal_ids(graph: TriageGraph, config: RunnableConfig) -> list[str]:
    """The ids of the gated calls waiting on the interrupt, in the order the middleware
    listed them: the last model turn, filtered to the gated tool."""
    messages = _all_messages(graph, config)
    last = next((m for m in reversed(messages) if isinstance(m, AIMessage)), None)
    if last is None:
        return []
    return [str(c["id"]) for c in last.tool_calls if c["name"] == GATED_TOOL]


def _decide(
    request: dict[str, Any],
    tool_call_ids: list[str],
    decide: DecideFn,
    decisions: list[HumanDecision],
) -> list[dict[str, Any]]:
    resume: list[dict[str, Any]] = []
    actions = request["action_requests"]
    if len(tool_call_ids) != len(actions):
        raise RuntimeError(
            f"{len(actions)} actions await a decision but {len(tool_call_ids)} gated calls "
            "are pending"
        )
    for action, tool_call_id in zip(actions, tool_call_ids, strict=True):
        proposal = dict(action["args"])
        decision = decide(proposal)
        decisions.append(
            HumanDecision(
                tool_call_id=tool_call_id,
                proposal=proposal,
                decision=(
                    DispositionDecision.accepted
                    if decision.accept
                    else DispositionDecision.rejected
                ),
                reason=decision.reason,
            )
        )
        if decision.accept:
            resume.append({"type": "approve"})
        elif decision.reason:
            resume.append({"type": "reject", "message": decision.reason})
        else:
            resume.append({"type": "reject"})
    return resume


def usage_records(messages: list[AnyMessage], model_id: str) -> list[ModelUsageRecord]:
    """One record per model turn that reported usage, numbered by the turn's position."""
    records: list[ModelUsageRecord] = []
    step = 0
    for message in messages:
        if not isinstance(message, AIMessage):
            continue
        usage = message.usage_metadata
        if usage is not None:
            in_details = usage.get("input_token_details") or {}
            out_details = usage.get("output_token_details") or {}
            records.append(
                ModelUsageRecord(
                    step=step,
                    model=model_id,
                    input_tokens=usage["input_tokens"],
                    output_tokens=usage["output_tokens"],
                    total_tokens=usage["total_tokens"],
                    input_token_details=InputTokenDetails(
                        audio=in_details.get("audio", 0),
                        cache_read=in_details.get("cache_read", 0),
                        cache_creation=in_details.get("cache_creation", 0),
                    ),
                    output_token_details=OutputTokenDetails(
                        audio=out_details.get("audio", 0),
                        reasoning=out_details.get("reasoning", 0),
                    ),
                )
            )
        step += 1
    return records
