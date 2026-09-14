"""LangChain tools built from a ``ToolRunner``, so every call the model makes is
journalled by the slice 2 pipeline by construction.

The model sees the request model's JSON schema; the runner validates the arguments. A
call with wrong arguments must reach the journal as ``invalid_arguments``, and a
validation error raised by LangChain before the runner would leave it unjournalled.
"""

import json
from typing import Any

from langchain_core.messages import AIMessage
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.prebuilt.tool_node import ToolRuntime

from alert_forensics.tools.adapter import ToolDefinition
from alert_forensics.tools.definitions import DEFINITIONS
from alert_forensics.tools.runner import ToolRunner

ToolContent = tuple[str, dict[str, Any]]


def runner_tools(runner: ToolRunner) -> list[BaseTool]:
    """One tool per adapter the runner has, in the registry's order."""
    return [
        _tool(runner, runner.adapters[name].definition)
        for name in DEFINITIONS
        if name in runner.adapters
    ]


def _tool(runner: ToolRunner, definition: ToolDefinition[Any, Any, Any]) -> BaseTool:
    def call(runtime: ToolRuntime[Any, Any], **arguments: Any) -> ToolContent:
        if runtime.tool_call_id is None:
            raise RuntimeError(f"{definition.name} was called outside a tool node, without an id")
        record = runner.invoke(
            tool_call_id=runtime.tool_call_id,
            step=_step(runtime),
            tool_name=definition.name,
            arguments=arguments,
            turn_siblings=_siblings(runtime, runtime.tool_call_id),
        )
        content = json.dumps(record.redacted_response, ensure_ascii=False)
        return content, record.model_dump(mode="json")

    return StructuredTool(
        name=definition.name,
        description=definition.description,
        args_schema=definition.request_model.model_json_schema(),
        func=call,
        response_format="content_and_artifact",
    )


def _step(runtime: ToolRuntime[Any, Any]) -> int:
    """Index of the model turn that emitted this call: the tool node sees the emitting
    ``AIMessage`` already in the state, so it is the count of model turns less one."""
    turns = sum(1 for m in _messages(runtime) if isinstance(m, AIMessage))
    return max(turns - 1, 0)


def _siblings(runtime: ToolRuntime[Any, Any], tool_call_id: str) -> list[str]:
    """Names of the other calls in the turn that emitted this one."""
    last = next((m for m in reversed(_messages(runtime)) if isinstance(m, AIMessage)), None)
    if last is None:
        return []
    return [str(c["name"]) for c in last.tool_calls if c.get("id") != tool_call_id]


def _messages(runtime: ToolRuntime[Any, Any]) -> list[Any]:
    state = runtime.state
    return list(state.get("messages", [])) if isinstance(state, dict) else []
