"""The agent graph: investigate, ground, repair, finish.

Built once per investigation around one ``ToolRunner``. The investigation is a
``create_agent`` subgraph with the human-in-the-loop middleware; the correction loop is
the outer graph. Compiled on a checkpointer so the proposal interrupt can resume.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Literal, NotRequired, TypedDict

from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware, HumanInTheLoopMiddleware
from langchain.agents.middleware.types import AgentState, ModelRequest, ModelResponse, hook_config
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.runtime import Runtime
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
from alert_forensics.tools.ordering import check_order, offerable
from alert_forensics.tools.runner import ToolRunner

GATED_TOOL = PROPOSE_ALERT_DISPOSITION.name


class OrderingMiddleware(AgentMiddleware[Any, Any]):
    """Enforces the ordering rules the definitions declare, in the graph.

    Two halves. Before a model call, a tool that needs evidence is left out of the bound
    tools while the journal holds no ``ok`` record. After a model call, a turn that
    breaks a rule jumps straight to the tool node, past the human-in-the-loop interrupt:
    the runner denies the call and journals it, and a proposal that will be refused is
    never put in front of the analyst. Listed after the interrupt middleware, because
    ``after_model`` hooks run in reverse order of the list.
    """

    def __init__(self, runner: ToolRunner) -> None:
        super().__init__()
        self.runner = runner

    def wrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], ModelResponse[Any]],
    ) -> ModelResponse[Any]:
        offered = [t for t in request.tools if self._offered(t)]
        if len(offered) != len(request.tools):
            request = request.override(tools=offered)
        return handler(request)

    def _offered(self, tool: BaseTool | dict[str, Any]) -> bool:
        name = tool.name if isinstance(tool, BaseTool) else None
        adapter = self.runner.adapters.get(name) if name else None
        return adapter is None or offerable(adapter.definition, self.runner.records)

    @hook_config(can_jump_to=["tools"])
    def after_model(self, state: AgentState[Any], runtime: Runtime[Any]) -> dict[str, Any] | None:
        last = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)
        if last is None or not self._breaks_a_rule(last):
            return None
        return {"jump_to": "tools"}

    def _breaks_a_rule(self, message: AIMessage) -> bool:
        for call in message.tool_calls:
            adapter = self.runner.adapters.get(call["name"])
            if adapter is None:
                continue
            siblings = [c["name"] for c in message.tool_calls if c.get("id") != call.get("id")]
            denial = check_order(
                self.runner.principal, adapter.definition, self.runner.records, siblings
            )
            if denial is not None:
                return True
        return False


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
            ),
            OrderingMiddleware(runner),
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
