"""Investigation trace: the journal a replay viewer and the grounding validator both read.

A trace answers three questions on its own: what happened (``records``), what did it rest
on (``alert`` and each record's redacted response), and what did it consume (``usage``).
The raw upstream response never enters the trace; it is held by reference and hash.
"""

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Any

from pydantic import (
    AwareDatetime,
    Field,
    JsonValue,
    SerializationInfo,
    StringConstraints,
    field_serializer,
    model_validator,
)

from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.contracts.alert import Alert


class SourceSystem(StrEnum):
    """The system a tool reads from. Shared by tool records and observed facts."""

    defender = "defender"
    splunk = "splunk"
    virustotal = "virustotal"
    graph_security = "graph_security"
    attack = "attack"
    runbook = "runbook"


class ToolOutcome(StrEnum):
    """How a tool call ended. Only ``ok`` returned data a fact can rest on."""

    ok = "ok"
    error = "error"
    denied = "denied"


Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class ToolCallRecord(ContractModel):
    """One journalled tool call."""

    tool_call_id: NonEmptyStr
    step: StrictNonNegativeInt
    """Index of the model turn that emitted this call. Parallel calls share a step."""
    tool_name: NonEmptyStr
    source_system: SourceSystem
    caller: NonEmptyStr
    """Identity the call was made under, e.g. the analyst role."""
    required_scope: NonEmptyStr
    """Scope the tool declares. On a ``denied`` outcome this is the scope that was missing."""
    arguments: dict[str, JsonValue]
    started_at: AwareDatetime
    duration_us: StrictNonNegativeInt
    outcome: ToolOutcome
    redacted_response: JsonValue
    """The projection the model actually received, verbatim."""
    raw_response_ref: NonEmptyStr
    """Stable key into the out-of-context artifact store holding the raw response."""
    raw_response_sha256: Sha256Hex


class InputTokenDetails(ContractModel):
    audio: StrictNonNegativeInt = 0
    cache_read: StrictNonNegativeInt = 0
    cache_creation: StrictNonNegativeInt = 0


class OutputTokenDetails(ContractModel):
    audio: StrictNonNegativeInt = 0
    reasoning: StrictNonNegativeInt = 0


class ModelUsageRecord(ContractModel):
    """Token usage of one model turn, mirroring LangChain ``UsageMetadata``. No cost field:
    prices change, so cost is derived at read time from a price table."""

    step: StrictNonNegativeInt
    model: NonEmptyStr
    input_tokens: StrictNonNegativeInt
    output_tokens: StrictNonNegativeInt
    total_tokens: StrictNonNegativeInt
    input_token_details: InputTokenDetails = Field(default_factory=InputTokenDetails)
    output_token_details: OutputTokenDetails = Field(default_factory=OutputTokenDetails)


class InvestigationTrace(ContractModel):
    """The complete, self-contained record of one investigation."""

    investigation_id: NonEmptyStr
    alert: Alert
    started_at: AwareDatetime
    records: list[ToolCallRecord] = Field(default_factory=list)
    """Tool calls in journal order. Not sorted by time: parallel calls interleave."""
    usage: list[ModelUsageRecord] = Field(default_factory=list)

    @field_serializer("alert")
    def _alert_as_received(self, alert: Alert, info: SerializationInfo) -> Any:
        """Archive the alert as the source provided it, never with injected defaults."""
        if info.mode == "json":
            return alert.to_wire()
        return alert.model_dump(by_alias=True, exclude_unset=True)

    @model_validator(mode="after")
    def _no_duplicate_ids(self) -> "InvestigationTrace":
        seen_ids: set[str] = set()
        for record in self.records:
            if record.tool_call_id in seen_ids:
                raise ValueError(f"duplicate tool_call_id in trace: {record.tool_call_id!r}")
            seen_ids.add(record.tool_call_id)
        seen_steps: set[int] = set()
        for usage in self.usage:
            if usage.step in seen_steps:
                raise ValueError(f"duplicate usage step in trace: {usage.step}")
            seen_steps.add(usage.step)
        return self

    def find(self, tool_call_id: str) -> ToolCallRecord | None:
        """Return the record with this id, or None."""
        return next((r for r in self.records if r.tool_call_id == tool_call_id), None)


def hash_raw_response(raw: JsonValue) -> str:
    """SHA-256 of the canonical JSON form of a raw tool response.

    Canonical means sorted keys, compact separators and unescaped non-ASCII, so two
    semantically equal responses hash the same regardless of key order or formatting.
    """
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
