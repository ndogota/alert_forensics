"""``get_identity``: Splunk Enterprise Security Asset and Identity framework, identities."""

from pydantic import Field

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import LiveContract, ToolDefinition, ToolRequest, ToolView
from alert_forensics.tools.definitions._common import (
    SplunkResultsResponse,
    optional_str,
    split_multivalue,
    splunk_bool,
)


class GetIdentityRequest(ToolRequest):
    identity: str = Field(
        min_length=1, description="Username, user principal name or email to look up."
    )


class IdentityView(ToolView):
    found: bool
    identities: list[str]
    email: str | None
    priority: str | None
    business_unit: str | None
    categories: list[str]
    watchlist: bool | None
    managed_by: str | None
    start_date: str | None
    end_date: str | None
    work_city: str | None
    work_country: str | None


def _project(response: SplunkResultsResponse, request: GetIdentityRequest | None) -> IdentityView:
    if not response.results:
        return IdentityView(
            found=False,
            identities=[],
            email=None,
            priority=None,
            business_unit=None,
            categories=[],
            watchlist=None,
            managed_by=None,
            start_date=None,
            end_date=None,
            work_city=None,
            work_country=None,
        )
    row = response.results[0]
    return IdentityView(
        found=True,
        identities=split_multivalue(row.get("identity")),
        email=optional_str(row.get("email")),
        priority=optional_str(row.get("priority")),
        business_unit=optional_str(row.get("bunit")),
        categories=split_multivalue(row.get("category")),
        watchlist=splunk_bool(row.get("watchlist")),
        managed_by=optional_str(row.get("managedBy")),
        start_date=optional_str(row.get("startDate")),
        end_date=optional_str(row.get("endDate")),
        work_city=optional_str(row.get("work_city")),
        work_country=optional_str(row.get("work_country")),
    )


GET_IDENTITY = ToolDefinition(
    name="get_identity",
    description=(
        "Look up a user in the Splunk ES identity framework: priority, business unit, "
        "categories, watchlist flag, manager and employment dates. Priority drives urgency."
    ),
    source_system=SourceSystem.splunk,
    required_scope="identity:read",
    request_model=GetIdentityRequest,
    response_model=SplunkResultsResponse,
    view_model=IdentityView,
    projector=_project,
    live=LiveContract(
        status="fixture",
        system="Splunk Enterprise Security, Asset and Identity framework",
        endpoint=(
            "search/v2 job with '| inputlookup identity_lookup_expanded where identity=\"<value>\"'"
        ),
        auth="as search_siem",
        permission="read on the identity_lookup_expanded lookup",
        notes=(
            "Names, phone numbers and work coordinates are in the lookup and are dropped "
            "by the projection; email is kept as the join key."
        ),
    ),
)
