"""Shared pieces of the nine definitions: envelopes several APIs share, small readers."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import Field, JsonValue

from alert_forensics.tools.adapter import ToolResponse, ToolView
from alert_forensics.tools.definitions._columns import hunting_column_allowed

MAX_ROWS = 50
"""Tabular projections stop here and say so with ``truncated``."""

Row = dict[str, JsonValue]


def project_rows(
    rows: list[Row], declared: list[str], allowed: Callable[[str], bool]
) -> tuple[list[str], list[Row], int]:
    """Keep only allowlisted columns. Returns the kept column names in declared order
    (rows' order when nothing was declared), the projected rows, and how many distinct
    columns were dropped."""
    seen: list[str] = list(declared)
    for row in rows:
        for key in row:
            if key not in seen:
                seen.append(key)
    kept = [name for name in seen if allowed(name)]
    projected = [{k: v for k, v in row.items() if allowed(k)} for row in rows[:MAX_ROWS]]
    return kept, projected, len(seen) - len(kept)


class HuntingColumn(ToolResponse):
    name: str
    type: str | None = None


class HuntingResponse(ToolResponse):
    """Graph ``security/runHuntingQuery``: ``schema[] {name,type}`` plus ``results[]``."""

    schema_: list[HuntingColumn] = Field(default_factory=list, alias="schema")
    results: list[Row] = Field(default_factory=list)


class HuntingView(ToolView):
    columns: list[str]
    """Columns kept: those on the tool's allowlist, in the query's order."""
    row_count: int
    rows: list[Row]
    truncated: bool
    dropped_columns: int
    """Distinct columns the query returned that are not on the allowlist. A count, not
    names: the row is a projection and a dropped column cannot be asked for."""


def hunting_view(response: HuntingResponse) -> HuntingView:
    columns, rows, dropped = project_rows(
        response.results, [c.name for c in response.schema_], hunting_column_allowed
    )
    return HuntingView(
        columns=columns,
        row_count=len(response.results),
        rows=rows,
        truncated=len(response.results) > MAX_ROWS,
        dropped_columns=dropped,
    )


class SplunkField(ToolResponse):
    name: str


class SplunkMessage(ToolResponse):
    type: str | None = None
    text: str


class SplunkResultsResponse(ToolResponse):
    """Splunk ``search/v2/jobs/{sid}/results`` with ``output_mode=json``, plus the sid."""

    sid: str
    results: list[Row] = Field(default_factory=list)
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
