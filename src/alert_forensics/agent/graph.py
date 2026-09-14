"""The agent graph: investigate, ground, repair, finish.

Built once per investigation around one ``ToolRunner``. The investigation is a
``create_agent`` subgraph with the human-in-the-loop middleware; the correction loop is
the outer graph. Compiled on a checkpointer so the proposal interrupt can resume.
"""

from datetime import datetime
from typing import Annotated, Any, Literal, NotRequired, TypedDict

from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AnyMessage, HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Checkpointer

from alert_forensics.agent.prompts import REPAIR_SYSTEM_PROMPT, SYSTEM_PROMPT, repair_message
from alert_forensics.agent.strategy import output_strategy
from alert_forensics.agent.tools import runner_tools
from alert_forensics.artifact import CorrectionRecord
from alert_forensics.contracts import (
    Alert,
    InvestigationTrace,
    RunError,
    RunOutcome,
    TriageResult,
)
from alert_forensics.grounding import GroundingReport, validate_grounding
from alert_forensics.repair import CitationRepairs, apply_repairs, build_repair_instruction
from alert_forensics.tools.definitions.propose_alert_disposition import (
    PROPOSE_ALERT_DISPOSITION,
)
from alert_forensics.tools.runner import ToolRunner

GATED_TOOL = PROPOSE_ALERT_DISPOSITION.name


class TriageState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    structured_response: NotRequired[Any]
    """Written by the investigate subgraph: the first pass's ``TriageResult``."""
    result: NotRequired[TriageResult | None]
    report: NotRequired[GroundingReport | None]
    passes: NotRequired[int]
    corrections: NotRequired[list[CorrectionRecord]]
    outcome: NotRequired[RunOutcome | None]
    error: NotRequired[RunError | None]


TriageGraph = CompiledStateGraph[TriageState, Any, TriageState, TriageState]


def build_triage_graph(
    *,
    model: BaseChatModel,
    runner: ToolRunner,
    alert: Alert,
    started_at: datetime,
    max_corrections: int = 1,
    checkpointer: Checkpointer = None,
) -> TriageGraph:
    if max_corrections < 0:
        raise ValueError("max_corrections is zero or more")

    investigate = create_agent(
        model,
        tools=runner_tools(runner),
        system_prompt=SYSTEM_PROMPT,
        middleware=[
            HumanInTheLoopMiddleware(
                interrupt_on={GATED_TOOL: {"allowed_decisions": ["approve", "reject"]}},
                description_prefix="The agent proposes a disposition. Nothing is written.",
            )
        ],
        response_format=output_strategy(model, TriageResult),
        name="investigate",
    )
    repair_agent = create_agent(
        model,
        tools=[],
        system_prompt=REPAIR_SYSTEM_PROMPT,
        response_format=output_strategy(model, CitationRepairs),
        name="repair",
    )

    def trace() -> InvestigationTrace:
        return InvestigationTrace(
            investigation_id=runner.investigation_id,
            alert=alert,
            started_at=started_at,
            records=list(runner.records),
        )

    def ground(state: TriageState) -> dict[str, Any]:
        result = state.get("result")
        if result is None:
            produced = state.get("structured_response")
            result = produced if isinstance(produced, TriageResult) else None
        if result is None:
            return {
                "error": RunError(
                    kind="no_result",
                    message="the model ended the investigation without a structured result",
                ),
                "passes": 0,
            }
        report = validate_grounding(result, trace())
        return {"result": result, "report": report, "passes": max(state.get("passes", 0), 1)}

    def route(state: TriageState) -> Literal["repair", "finish"]:
        report = state.get("report")
        if state.get("error") is not None or report is None or report.is_grounded:
            return "finish"
        return "repair" if state.get("passes", 1) <= max_corrections else "finish"

    def repair(state: TriageState) -> dict[str, Any]:
        result = state["result"]
        report = state["report"]
        assert result is not None and report is not None
        instruction = build_repair_instruction(report, trace())
        output = repair_agent.invoke({"messages": [HumanMessage(repair_message(instruction))]})
        produced = output.get("structured_response")
        repairs = produced if isinstance(produced, CitationRepairs) else CitationRepairs()
        record = CorrectionRecord(instruction=instruction, repairs=repairs, report_before=report)
        return {
            "result": apply_repairs(result, report, repairs),
            "report": None,
            "corrections": [*state.get("corrections", []), record],
            "passes": state.get("passes", 1) + 1,
            "messages": output["messages"],
        }

    def finish(state: TriageState) -> dict[str, Any]:
        report = state.get("report")
        if state.get("error") is not None or report is None:
            return {"outcome": RunOutcome.failed_error}
        if report.is_grounded:
            return {"outcome": RunOutcome.completed}
        return {"outcome": RunOutcome.failed_ungrounded}

    builder: StateGraph[TriageState, Any, TriageState, TriageState] = StateGraph(TriageState)
    builder.add_node("investigate", investigate)
    builder.add_node("ground", ground)
    builder.add_node("repair", repair)
    builder.add_node("finish", finish)
    builder.add_edge(START, "investigate")
    builder.add_edge("investigate", "ground")
    builder.add_conditional_edges("ground", route, {"repair": "repair", "finish": "finish"})
    builder.add_edge("repair", "ground")
    builder.add_edge("finish", END)
    return builder.compile(checkpointer=checkpointer)
