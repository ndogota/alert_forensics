import json

import pytest
from langchain.agents.structured_output import ProviderStrategy, ToolStrategy
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from alert_forensics.agent import output_strategy
from alert_forensics.agent.scripted import (
    ScriptedCall,
    ScriptedChatModel,
    ScriptExhaustedError,
    StructuredTurn,
    TextTurn,
    ToolCallsTurn,
)


class Out(BaseModel):
    verdict: str


def noop(indicator: str) -> str:
    return indicator


LOOKUP = StructuredTool.from_function(noop, name="lookup_ioc", description="Look up.")
OUT_TOOL = StructuredTool.from_function(noop, name="Out", description="Structured output.")


def test_tool_call_turns_are_replayed_verbatim():
    model = ScriptedChatModel(
        script=[
            ToolCallsTurn(
                tool_calls=[ScriptedCall(id="tc-1", name="lookup_ioc", args={"indicator": "x"})]
            )
        ]
    )
    bound = model.bind_tools([LOOKUP])
    message = bound.invoke([HumanMessage("go")])
    assert isinstance(message, AIMessage)
    assert message.tool_calls == [
        {"name": "lookup_ioc", "args": {"indicator": "x"}, "id": "tc-1", "type": "tool_call"}
    ]
    assert message.usage_metadata is not None
    assert message.usage_metadata["input_tokens"] > 0
    assert message.usage_metadata["output_tokens"] > 0
    assert model.received == [[HumanMessage("go")]]


def test_a_structured_turn_renders_for_the_bound_strategy():
    payload = {"verdict": "fp"}
    provider = ScriptedChatModel(script=[StructuredTurn(payload=payload)])
    kwargs = ProviderStrategy(Out).to_model_kwargs()
    message = provider.bind_tools([LOOKUP], **kwargs).invoke([HumanMessage("go")])
    assert message.tool_calls == []
    assert json.loads(message.content) == payload

    tool = ScriptedChatModel(script=[StructuredTurn(payload=payload)])
    message = tool.bind_tools([LOOKUP, OUT_TOOL], tool_choice="any").invoke([HumanMessage("go")])
    assert len(message.tool_calls) == 1
    assert message.tool_calls[0]["name"] == "Out"
    assert message.tool_calls[0]["args"] == payload
    assert message.tool_calls[0]["id"]


def test_a_callable_turn_sees_the_messages_so_far():
    def decide(messages):
        assert isinstance(messages[0], SystemMessage)
        return TextTurn(text=f"saw {len(messages)} messages")

    model = ScriptedChatModel(script=[decide])
    message = model.invoke([SystemMessage("sys"), HumanMessage("go")])
    assert message.content == "saw 2 messages"


def test_an_exhausted_script_raises():
    model = ScriptedChatModel(script=[TextTurn(text="only one")])
    model.invoke([HumanMessage("go")])
    with pytest.raises(ScriptExhaustedError, match="1 turn"):
        model.invoke([HumanMessage("again")])


def test_the_scripted_client_needs_no_key_and_is_deterministic(monkeypatch):
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    a = ScriptedChatModel(script=[TextTurn(text="x")]).invoke([HumanMessage("go")])
    b = ScriptedChatModel(script=[TextTurn(text="x")]).invoke([HumanMessage("go")])
    assert a.usage_metadata == b.usage_metadata
    assert a.content == b.content


def test_output_strategy_is_decided_by_the_profile_never_by_the_name():
    provider = ScriptedChatModel(script=[], profile={"structured_output": True})
    assert isinstance(output_strategy(provider, Out), ProviderStrategy)
    tool = ScriptedChatModel(script=[], profile={"structured_output": False})
    assert isinstance(output_strategy(tool, Out), ToolStrategy)
    unknown = ScriptedChatModel(script=[], profile={"tool_calling": True})
    assert isinstance(output_strategy(unknown, Out), ToolStrategy)
    # A model named after one LangChain would guess supports native output, but with no
    # profile: the guess is not made.
    named = ScriptedChatModel(script=[], model_id="openai:gpt-4o", profile=None)
    assert named.profile is None
    assert isinstance(output_strategy(named, Out), ToolStrategy)


def test_the_output_binding_records_the_strategy_and_the_profile_values_it_read():
    from alert_forensics.agent import output_binding
    from alert_forensics.contracts import OutputBinding

    provider = ScriptedChatModel(script=[], profile={"structured_output": True})
    tool = ScriptedChatModel(script=[], profile={"structured_output": False})
    silent = ScriptedChatModel(script=[], profile={"tool_calling": True})
    unknown = ScriptedChatModel(script=[], profile=None)
    assert output_binding(provider) == OutputBinding(
        strategy="provider", profile_declared=True, structured_output=True, strict=True
    )
    assert output_binding(tool) == OutputBinding(
        strategy="tool", profile_declared=True, structured_output=False, strict=None
    )
    assert output_binding(silent) == OutputBinding(
        strategy="tool", profile_declared=True, structured_output=None, strict=None
    )
    assert output_binding(unknown) == OutputBinding(
        strategy="tool", profile_declared=False, structured_output=None, strict=None
    )


def test_the_provider_strategy_asks_for_strict_enforcement_and_the_tool_strategy_has_no_flag():
    """A profile declaring structured output says the provider can enforce a schema, not
    that the harness asked it to. The first OpenAI gate run was bound without the flag,
    the model added a key the schema forbids, and the run failed on the harness's knob."""
    provider = ScriptedChatModel(script=[], profile={"structured_output": True})
    strategy = output_strategy(provider, Out)
    assert isinstance(strategy, ProviderStrategy)
    assert strategy.schema_spec.strict is True
    assert strategy.to_model_kwargs()["response_format"]["json_schema"]["strict"] is True
    tool = ScriptedChatModel(script=[], profile={"structured_output": False})
    assert isinstance(output_strategy(tool, Out), ToolStrategy)


def test_the_scripted_client_records_the_tools_it_was_offered():
    model = ScriptedChatModel(script=[TextTurn(text="hi")], profile={"structured_output": True})
    bound = model.bind_tools([{"name": "a", "description": "A", "parameters": {}}])
    bound.invoke([HumanMessage("x")])
    assert model.offered_tools == [["a"]]
