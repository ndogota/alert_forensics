"""Shared pieces of the nine definitions: envelopes several APIs share, small readers."""

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, JsonValue

from alert_forensics.tools.adapter import ToolResponse, ToolView

MAX_ROWS = 50
"""Tabular projections stop here and say so with ``truncated``."""


class HuntingColumn(ToolResponse):
    name: str
    type: str | None = None


class HuntingResponse(ToolResponse):
    """Graph ``security/runHuntingQuery``: ``schema[] {name,type}`` plus ``results[]``."""

    schema_: list[HuntingColumn] = Field(default_factory=list, alias="schema")
    results: list[dict[str, JsonValue]] = Field(default_factory=list)


class HuntingView(ToolView):
    columns: list[str]
    row_count: int
    rows: list[dict[str, JsonValue]]
    truncated: bool


def hunting_view(response: HuntingResponse) -> HuntingView:
    columns = [c.name for c in response.schema_]
    if not columns and response.results:
        columns = list(response.results[0])
    return HuntingView(
        columns=columns,
        row_count=len(response.results),
        rows=response.results[:MAX_ROWS],
        truncated=len(response.results) > MAX_ROWS,
    )


class SplunkField(ToolResponse):
    name: str


class SplunkMessage(ToolResponse):
    type: str | None = None
    text: str


class SplunkResultsResponse(ToolResponse):
    """Splunk ``search/v2/jobs/{sid}/results`` with ``output_mode=json``, plus the sid."""

    sid: str
    results: list[dict[str, JsonValue]] = Field(default_factory=list)
    fields: list[SplunkField] = Field(default_factory=list)
    preview: bool = False
    messages: list[SplunkMessage] = Field(default_factory=list)


def split_multivalue(value: JsonValue) -> list[str]:
    """Splunk lookups carry multivalues as pipe-delimited strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    text = str(value)
    return [part for part in text.split("|") if part]


def splunk_bool(value: JsonValue) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "y", "t"}


def optional_str(value: JsonValue) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def epoch_to_iso(value: Any) -> str | None:
    """VirusTotal dates are unix epochs. The model receives ISO 8601 in UTC."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None
