"""The pipeline every tool call travels through, whatever the adapter behind it.

Scope check, argument validation, fetch, store the raw out of context, validate the
shape, project, redact, journal. Nothing raises into the agent: every way a call can
fail ends as a ``ToolCallRecord`` with a structured response the model can read.
"""

import threading
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import JsonValue, ValidationError

from alert_forensics.contracts import SourceSystem, ToolCallRecord, ToolOutcome
from alert_forensics.tools.adapter import (
    ToolAdapter,
    ToolDefinition,
    ToolFailure,
    UpstreamError,
)
from alert_forensics.tools.definitions import DEFINITIONS
from alert_forensics.tools.ordering import check_order
from alert_forensics.tools.redaction import redact
from alert_forensics.tools.scope import Principal, check_scope
from alert_forensics.tools.store import RawResponseStore

AnyDefinition = ToolDefinition[Any, Any, Any]
AnyAdapter = ToolAdapter[Any, Any, Any]


class ToolRunner:
    """Executes tool calls for one investigation and journals every one of them."""

    def __init__(
        self,
        adapters: Iterable[AnyAdapter],
        principal: Principal,
        store: RawResponseStore,
        investigation_id: str,
        clock: Callable[[], datetime] | None = None,
        on_record: Callable[[ToolCallRecord], None] | None = None,
    ) -> None:
        self.adapters: dict[str, AnyAdapter] = {}
        for adapter in adapters:
            name = adapter.definition.name
            if name in self.adapters:
                raise ValueError(f"two adapters registered for tool {name!r}")
            self.adapters[name] = adapter
        self.principal = principal
        self.store = store
        self.investigation_id = investigation_id
        self.clock = clock or (lambda: datetime.now(UTC))
        self.records: list[ToolCallRecord] = []
        self.on_record = on_record
        """Called with each record as it is journalled. A view over the journal, for
        progress; the journal itself is ``records``."""
        self._lock = threading.Lock()
        """One call at a time: the journal is a sequence, and a duplicate id is caught
        before anything runs even when a caller invokes from several threads."""

    def invoke(
        self,
        *,
        tool_call_id: str,
        step: int,
        tool_name: str,
        arguments: dict[str, JsonValue],
        turn_siblings: Sequence[str],
    ) -> ToolCallRecord:
        """``turn_siblings`` names the other calls the model emitted in the same turn;
        the ordering rules read it, the journal does not. It has no default on purpose:
        an empty default would read as "no siblings", which reads as "rule satisfied",
        and a call site that forgot it would silently disable ``alone_in_turn``."""
        with self._lock:
            return self._invoke(tool_call_id, step, tool_name, arguments, turn_siblings)

    def _invoke(
        self,
        tool_call_id: str,
        step: int,
        tool_name: str,
        arguments: dict[str, JsonValue],
        turn_siblings: Sequence[str],
    ) -> ToolCallRecord:
        if any(r.tool_call_id == tool_call_id for r in self.records):
            raise ValueError(f"tool_call_id {tool_call_id!r} was already journalled")
        started_at = self.clock()
        t0 = time.perf_counter_ns()
        outcome, raw, view, definition = self._execute(tool_name, arguments, turn_siblings)
        duration_us = (time.perf_counter_ns() - t0) // 1000
        stored = self.store.put(self.investigation_id, tool_call_id, raw)
        record = ToolCallRecord(
            tool_call_id=tool_call_id,
            step=step,
            tool_name=tool_name,
            source_system=definition.source_system if definition else SourceSystem.none,
            caller=self.principal.name,
            required_scope=definition.required_scope if definition else "none",
            arguments=arguments,
            started_at=started_at,
            duration_us=duration_us,
            outcome=outcome,
            redacted_response=view,
            raw_response_ref=stored.ref,
            raw_response_sha256=stored.sha256,
        )
        self.records.append(record)
        if self.on_record is not None:
            self.on_record(record)
        return record

    def _execute(
        self, tool_name: str, arguments: dict[str, JsonValue], turn_siblings: Sequence[str]
    ) -> tuple[ToolOutcome, JsonValue, JsonValue, AnyDefinition | None]:
        """Run the pipeline. Returns outcome, the raw to store, the view for the model,
        and the definition when one exists."""
        adapter = self.adapters.get(tool_name)
        if adapter is None:
            known = DEFINITIONS.get(tool_name)
            detail = (
                f"no adapter registered for {tool_name!r}"
                if known is not None
                else f"no tool named {tool_name!r}"
            )
            failure = _failure("unknown_tool", tool_name, detail)
            return ToolOutcome.error, failure, failure, known
        definition = adapter.definition

        denial = check_scope(self.principal, definition) or check_order(
            self.principal, definition, self.records, turn_siblings
        )
        if denial is not None:
            dumped: JsonValue = denial.model_dump(mode="json")
            return ToolOutcome.denied, dumped, dumped, definition

        try:
            request = definition.request_model.model_validate(arguments)
        except ValidationError as exc:
            failure = _failure("invalid_arguments", tool_name, _validation_summary(exc))
            return ToolOutcome.error, failure, failure, definition

        try:
            raw = adapter.fetch(request)
        except UpstreamError as exc:
            failure = _failure(exc.kind, tool_name, exc.detail)
            return ToolOutcome.error, failure, failure, definition

        try:
            response = definition.response_model.model_validate(raw)
        except ValidationError as exc:
            failure = _failure(
                "malformed_response",
                tool_name,
                "upstream response does not match the declared shape: " + _validation_summary(exc),
            )
            return ToolOutcome.error, raw, failure, definition

        view = redact(definition.project(response, request).model_dump(mode="json"))
        return ToolOutcome.ok, raw, view, definition


def _failure(kind: Any, tool: str, detail: str) -> JsonValue:
    dumped: JsonValue = ToolFailure(error=kind, tool=tool, detail=detail).model_dump(mode="json")
    return dumped


def _validation_summary(exc: ValidationError) -> str:
    """Field paths and messages only. Never the offending input values: on a malformed
    upstream response those may be exactly what redaction exists to keep out."""
    parts = []
    for error in exc.errors(include_input=False, include_url=False):
        location = ".".join(str(p) for p in error["loc"]) or "<root>"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)
