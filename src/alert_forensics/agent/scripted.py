"""The scripted client: a chat model stand-in that replays a script. No key, no network.

A script is a sequence of turns. A turn is a set of tool calls with their ids, a
structured output payload, plain text, or a callable that receives the messages so far
and returns one of those. A structured turn is rendered the way the bound strategy
expects: JSON content under ``ProviderStrategy``, a call to the structured-output tool
under ``ToolStrategy``, so one script exercises both.
"""

import json
from collections.abc import Callable, Sequence
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models import LanguageModelInput
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.messages.tool import ToolCall
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import Field, JsonValue, PrivateAttr

from alert_forensics.contracts import (
    Alert,
    DeviceEvidence,
    FileEvidence,
    IpEvidence,
    UrlEvidence,
    UserEvidence,
)
from alert_forensics.contracts._base import ContractModel, NonEmptyStr


class ScriptedCall(ContractModel):
    id: NonEmptyStr
    name: NonEmptyStr
    args: dict[str, JsonValue] = Field(default_factory=dict)


class ToolCallsTurn(ContractModel):
    tool_calls: list[ScriptedCall] = Field(min_length=1)


class StructuredTurn(ContractModel):
    payload: dict[str, JsonValue]
    schema_name: str | None = None
    """Under ``ToolStrategy``, the structured tool to call. Default: the last bound tool,
    which is where ``create_agent`` puts it."""


class TextTurn(ContractModel):
    text: str


Turn = ToolCallsTurn | StructuredTurn | TextTurn
ScriptStep = Turn | Callable[[list[BaseMessage]], Turn]


class ScriptExhaustedError(Exception):
    """The script had nothing left to say."""


class ScriptedChatModel(BaseChatModel):
    script: Sequence[ScriptStep]
    model_id: str = "scripted:demo"
    _cursor: int = PrivateAttr(default=0)
    _received: list[list[BaseMessage]] = PrivateAttr(default_factory=list)
    _offered_tools: list[list[str]] = PrivateAttr(default_factory=list)

    @property
    def received(self) -> list[list[BaseMessage]]:
        """The messages each model call received, in order. What the tests inspect."""
        return self._received

    @property
    def offered_tools(self) -> list[list[str]]:
        """The tool names bound on each model call, in order: what the model was offered."""
        return self._offered_tools

    @property
    def _llm_type(self) -> str:
        return "scripted"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"model_id": self.model_id}

    def bind_tools(
        self,
        tools: Sequence[dict[str, Any] | type | Callable[..., Any] | BaseTool],
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> Runnable[LanguageModelInput, AIMessage]:
        bound: dict[str, Any] = {"tools": [convert_to_openai_tool(t) for t in tools], **kwargs}
        if tool_choice is not None:
            bound["tool_choice"] = tool_choice
        return self.bind(**bound)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        self._received.append(list(messages))
        self._offered_tools.append([str(t["function"]["name"]) for t in kwargs.get("tools") or []])
        if self._cursor >= len(self.script):
            raise ScriptExhaustedError(
                f"the script ran out after {len(self.script)} turn"
                f"{'' if len(self.script) == 1 else 's'}"
            )
        step = self.script[self._cursor]
        self._cursor += 1
        turn = step(list(messages)) if callable(step) else step
        message = self._render(turn, kwargs)
        prompt_chars = sum(len(str(m.content)) for m in messages)
        output_chars = len(str(message.content)) + len(json.dumps(message.tool_calls))
        input_tokens = prompt_chars // 4 + 1
        output_tokens = output_chars // 4 + 1
        message.usage_metadata = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
        return ChatResult(generations=[ChatGeneration(message=message)])

    def _render(self, turn: Turn, kwargs: dict[str, Any]) -> AIMessage:
        if isinstance(turn, ToolCallsTurn):
            calls: list[ToolCall] = [
                ToolCall(name=c.name, args=dict(c.args), id=c.id, type="tool_call")
                for c in turn.tool_calls
            ]
            return AIMessage(content="", tool_calls=calls)
        if isinstance(turn, TextTurn):
            return AIMessage(content=turn.text)
        if "response_format" in kwargs:
            return AIMessage(content=json.dumps(turn.payload, ensure_ascii=False))
        bound_tools: list[dict[str, Any]] = kwargs.get("tools") or []
        if not bound_tools:
            return AIMessage(content=json.dumps(turn.payload, ensure_ascii=False))
        name = turn.schema_name or str(bound_tools[-1]["function"]["name"])
        call = ToolCall(
            name=name, args=dict(turn.payload), id=f"so-{self._cursor}", type="tool_call"
        )
        return AIMessage(content="", tool_calls=[call])


# --- The demo script ---------------------------------------------------------------


def demo_script(alert: Alert) -> list[ScriptStep]:
    """A script derived from the alert's evidence. It calls the read tools on the
    entities the alert names, proposes an inconclusive disposition, and then states one
    fact per call that succeeded. It reasons about nothing; it demonstrates the
    mechanism."""
    calls = _demo_calls(alert)
    proposal = ScriptedCall(
        id="tc-propose",
        name="propose_alert_disposition",
        args={
            "verdict": "inconclusive",
            "recommended_action": (
                "Run the investigation with a model. The scripted client replays tool calls "
                "and does not weigh the evidence."
            ),
            "escalate": False,
            "summary": (
                f"Scripted demonstration for alert {alert.id!r}: {len(calls)} tool calls "
                "were replayed against the fixtures; no reasoning took place."
            ),
        },
    )
    return [
        ToolCallsTurn(tool_calls=calls),
        ToolCallsTurn(tool_calls=[proposal]),
        _demo_result,
    ]


def _demo_calls(alert: Alert) -> list[ScriptedCall]:
    upn: str | None = None
    account: str | None = None
    devices: list[str] = []
    indicators: list[str] = []
    for item in alert.evidence:
        if isinstance(item, UserEvidence) and item.user_account is not None:
            upn = upn or item.user_account.user_principal_name
            account = account or item.user_account.account_name
        elif isinstance(item, DeviceEvidence) and item.device_dns_name:
            devices.append(item.device_dns_name)
        elif isinstance(item, IpEvidence) and item.ip_address:
            indicators.append(item.ip_address)
        elif isinstance(item, FileEvidence) and item.file_details and item.file_details.sha256:
            indicators.append(item.file_details.sha256)
        elif isinstance(item, UrlEvidence) and item.url:
            indicators.append(item.url)
    calls: list[ScriptedCall] = []
    if upn:
        calls.append(
            ScriptedCall(
                id="tc-related", name="get_related_alerts", args={"user_principal_name": upn}
            )
        )
        calls.append(
            ScriptedCall(
                id="tc-signins",
                name="search_events",
                args={
                    "query": (
                        f"SigninLogs | where UserPrincipalName == '{upn}' | project Timestamp, "
                        "IPAddress, City, Country, ResultType, ConditionalAccessStatus"
                    ),
                    "timespan": "P7D",
                },
            )
        )
        calls.append(
            ScriptedCall(
                id="tc-identity",
                name="get_identity",
                args={"identity": account or upn.split("@", 1)[0]},
            )
        )
    elif alert.incident_id:
        calls.append(
            ScriptedCall(
                id="tc-related",
                name="get_related_alerts",
                args={"incident_id": alert.incident_id},
            )
        )
    for n, device in enumerate(dict.fromkeys(devices), start=1):
        calls.append(ScriptedCall(id=f"tc-asset-{n}", name="get_asset", args={"asset": device}))
    for n, indicator in enumerate(dict.fromkeys(indicators), start=1):
        calls.append(
            ScriptedCall(id=f"tc-ioc-{n}", name="lookup_ioc", args={"indicator": indicator})
        )
    for technique in alert.mitre_techniques:
        calls.append(
            ScriptedCall(
                id=f"tc-attack-{technique}",
                name="get_attack_technique",
                args={"technique_id": technique},
            )
        )
    calls.append(
        ScriptedCall(
            id="tc-runbook", name="search_runbook", args={"query": alert.title, "top_k": 3}
        )
    )
    return calls


def _demo_result(messages: list[BaseMessage]) -> Turn:
    arguments: dict[str, dict[str, JsonValue]] = {}
    for message in messages:
        if isinstance(message, AIMessage):
            for call in message.tool_calls:
                arguments[str(call["id"])] = dict(call["args"])
    facts: list[JsonValue] = []
    for message in messages:
        if not isinstance(message, ToolMessage) or message.name == "propose_alert_disposition":
            continue
        try:
            content = json.loads(str(message.content))
        except ValueError:
            continue
        if not isinstance(content, dict) or "error" in content:
            continue
        args = json.dumps(arguments.get(message.tool_call_id, {}), ensure_ascii=False)
        facts.append(
            {
                "statement": f"{message.name} returned a result for {args}.",
                "evidence": [message.tool_call_id],
            }
        )
    return StructuredTurn(
        payload={
            "verdict": "inconclusive",
            "confidence": 0.0,
            "mitre_techniques": [],
            "observed_facts": facts,
            "assumptions": [],
            "missing_context": [
                {
                    "what": "A model's reading of the evidence",
                    "why_it_matters": (
                        "The scripted client replays tool calls and reasons about nothing; "
                        "the verdict is inconclusive by construction."
                    ),
                    "how_to_obtain": "Run again with --model provider:name instead of --scripted.",
                }
            ],
            "recommended_action": "Run the investigation with a model.",
            "escalate": False,
        }
    )
