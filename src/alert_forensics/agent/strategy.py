"""Structured output strategy, decided from the model profile and nothing else."""

from typing import Any

from langchain.agents.structured_output import ProviderStrategy, ToolStrategy
from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import BaseModel

from alert_forensics.contracts import OutputBinding

OutputStrategy = ProviderStrategy[Any] | ToolStrategy[Any]


def output_binding(model: BaseChatModel) -> OutputBinding:
    """The strategy for this model and the profile values that decided it, recorded on
    the artifact so a recording says how it was bound.

    LangChain's automatic choice falls back to matching model names when a profile is
    missing. That fallback is not used: a strategy chosen from a name is a guess, and the
    profile exists to replace the guess. A model with no profile gets ``ToolStrategy``,
    which every tool-calling model supports.
    """
    profile = model.profile
    value = profile.get("structured_output") if profile is not None else None
    read = value if isinstance(value, bool) else None
    provider = read is True
    return OutputBinding(
        strategy="provider" if provider else "tool",
        profile_declared=profile is not None,
        structured_output=read,
        strict=True if provider else None,
    )


def output_strategy(model: BaseChatModel, schema: type[BaseModel]) -> OutputStrategy:
    """``ProviderStrategy`` when the profile says the provider enforces a schema natively,
    ``ToolStrategy`` otherwise. Neither strategy retries a malformed output: unparseable
    structured output is a failed run, not a hidden extra pass.

    The provider strategy is asked for strict enforcement, always. A profile declaring
    structured output says the provider can enforce a schema, not that it was asked to:
    without the flag the OpenAI client sends the schema as non-strict, and the first
    OpenAI gate run failed on a key the schema forbids. The Anthropic and Google clients
    drop the flag; the tool strategy has none.
    """
    if output_binding(model).strategy == "provider":
        return ProviderStrategy(schema, strict=True)
    return ToolStrategy(schema, handle_errors=False)
