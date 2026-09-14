"""``search_siem``: Splunk search v2, a job then its results."""

from pydantic import Field

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import LiveContract, ToolDefinition, ToolRequest, ToolView
from alert_forensics.tools.definitions._common import MAX_ROWS, SplunkResultsResponse


class SearchSiemRequest(ToolRequest):
    search: str = Field(min_length=1, description="SPL. A leading 'search' is optional.")
    earliest_time: str = Field(default="-24h", min_length=1)
    latest_time: str = Field(default="now", min_length=1)


class SiemView(ToolView):
    sid: str
    fields: list[str]
    row_count: int
    rows: list[dict[str, object]]
    truncated: bool
    messages: list[str]


def _project(response: SplunkResultsResponse, request: SearchSiemRequest | None) -> SiemView:
    fields = [f.name for f in response.fields]
    if not fields and response.results:
        fields = list(response.results[0])
    return SiemView(
        sid=response.sid,
        fields=fields,
        row_count=len(response.results),
        rows=[dict(row) for row in response.results[:MAX_ROWS]],
        truncated=len(response.results) > MAX_ROWS,
        messages=[m.text for m in response.messages],
    )


SEARCH_SIEM = ToolDefinition(
    name="search_siem",
    description=(
        "Run an SPL search in Splunk Enterprise Security over the given time range. "
        "Returns the search id, the field names and the result rows."
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
