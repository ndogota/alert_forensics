"""``search_siem``: Splunk search v2, a job then its results."""

from pydantic import Field

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import LiveContract, ToolDefinition, ToolRequest, ToolView
from alert_forensics.tools.definitions._columns import splunk_field_allowed
from alert_forensics.tools.definitions._common import (
    MAX_ROWS,
    Row,
    SplunkResultsResponse,
    project_rows,
)


class SearchSiemRequest(ToolRequest):
    search: str = Field(min_length=1, description="SPL. A leading 'search' is optional.")
    earliest_time: str = Field(default="-24h", min_length=1)
    latest_time: str = Field(default="now", min_length=1)


class SiemView(ToolView):
    sid: str
    fields: list[str]
    """Fields kept: those on the tool's allowlist, in the search's order."""
    row_count: int
    rows: list[Row]
    truncated: bool
    dropped_columns: int
    """Distinct fields the search returned that are not on the allowlist, as a count."""
    messages: list[str]


def _project(response: SplunkResultsResponse, request: SearchSiemRequest | None) -> SiemView:
    fields, rows, dropped = project_rows(
        response.results, [f.name for f in response.fields], splunk_field_allowed
    )
    return SiemView(
        sid=response.sid,
        fields=fields,
        row_count=len(response.results),
        rows=rows,
        truncated=len(response.results) > MAX_ROWS,
        dropped_columns=dropped,
        messages=[m.text for m in response.messages],
    )


SEARCH_SIEM = ToolDefinition(
    name="search_siem",
    description=(
        "Run an SPL search in Splunk Enterprise Security over the given time range. "
        "Returns the search id, the field names and the result rows. Only CIM fields and "
        "aggregates over them are returned; _raw never is. Use | table or | stats."
    ),
    source_system=SourceSystem.splunk,
    required_scope="siem:search",
    request_model=SearchSiemRequest,
    response_model=SplunkResultsResponse,
    view_model=SiemView,
    projector=_project,
    live=LiveContract(
        status="fixture",
        system="Splunk Enterprise REST API",
        endpoint=(
            "POST /services/search/v2/jobs then GET /services/search/v2/jobs/{sid}/results"
            "?output_mode=json"
        ),
        auth="Bearer token (Authorization: Bearer <token>) or session key",
        permission="Splunk capability 'search' plus read access to the indexes searched",
        notes="Poll the job until dispatchState is DONE before reading results.",
    ),
)
