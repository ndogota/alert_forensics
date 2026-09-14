"""``search_events``: Defender advanced hunting through Graph ``security/runHuntingQuery``."""

from pydantic import Field

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import LiveContract, ToolDefinition, ToolRequest
from alert_forensics.tools.definitions._common import (
    HuntingResponse,
    HuntingView,
    hunting_view,
)


class SearchEventsRequest(ToolRequest):
    query: str = Field(min_length=1, description="KQL against the advanced hunting schema.")
    timespan: str = Field(
        default="P7D",
        pattern=r"^P(?:\d+D|T\d+H|\d+DT\d+H)$",
        description="ISO 8601 duration looking back from now, e.g. P7D or PT12H.",
    )


def _project(response: HuntingResponse, request: SearchEventsRequest | None) -> HuntingView:
    return hunting_view(response)


SEARCH_EVENTS = ToolDefinition(
    name="search_events",
    description=(
        "Run a KQL query against Microsoft Defender advanced hunting tables such as "
        "SigninLogs, DeviceEvents, DeviceNetworkEvents, EmailEvents or CloudAppEvents. "
        "Returns the result columns and rows. Only standard schema columns and KQL "
        "aggregates over them are returned; AdditionalFields never is. Use | project."
    ),
    source_system=SourceSystem.defender,
    required_scope="hunting:read",
    request_model=SearchEventsRequest,
    response_model=HuntingResponse,
    view_model=HuntingView,
    projector=_project,
    live=LiveContract(
        status="fixture",
        system="Microsoft Graph security API",
        endpoint="POST https://graph.microsoft.com/v1.0/security/runHuntingQuery",
        auth="OAuth 2.0 bearer token from Entra ID (client credentials or delegated)",
        permission="ThreatHunting.Read.All",
        notes=(
            "Body {Query, Timespan}. Response {schema:[{name,type}], results:[...]}. "
            "Rows above 50 are dropped from the view and flagged as truncated."
        ),
    ),
)
