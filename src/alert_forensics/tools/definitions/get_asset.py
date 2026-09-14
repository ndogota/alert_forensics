"""``get_asset``: Splunk Enterprise Security Asset and Identity framework, assets."""

from pydantic import Field

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import LiveContract, ToolDefinition, ToolRequest, ToolView
from alert_forensics.tools.definitions._common import (
    SplunkResultsResponse,
    optional_str,
    split_multivalue,
    splunk_bool,
)


class GetAssetRequest(ToolRequest):
    asset: str = Field(min_length=1, description="Hostname, DNS name or IP address.")


class AssetView(ToolView):
    found: bool
    nt_host: str | None
    dns: str | None
    ip: str | None
    owner: str | None
    priority: str | None
    business_unit: str | None
    categories: list[str]
    pci_domain: str | None
    country: str | None
    is_expected: bool | None
    should_update: bool | None
    requires_av: bool | None


def _project(response: SplunkResultsResponse, request: GetAssetRequest | None) -> AssetView:
    if not response.results:
        return AssetView(
            found=False,
            nt_host=None,
            dns=None,
            ip=None,
            owner=None,
            priority=None,
            business_unit=None,
            categories=[],
            pci_domain=None,
            country=None,
            is_expected=None,
            should_update=None,
            requires_av=None,
        )
    row = response.results[0]
    return AssetView(
        found=True,
        nt_host=optional_str(row.get("nt_host")),
        dns=optional_str(row.get("dns")),
        ip=optional_str(row.get("ip")),
        owner=optional_str(row.get("owner")),
        priority=optional_str(row.get("priority")),
        business_unit=optional_str(row.get("bunit")),
        categories=split_multivalue(row.get("category")),
        pci_domain=optional_str(row.get("pci_domain")),
        country=optional_str(row.get("country")),
        is_expected=splunk_bool(row.get("is_expected")),
        should_update=splunk_bool(row.get("should_update")),
        requires_av=splunk_bool(row.get("requires_av")),
    )


GET_ASSET = ToolDefinition(
    name="get_asset",
    description=(
        "Look up a device in the Splunk ES asset framework: criticality (priority), owner, "
        "business unit, categories, PCI domain and compliance expectations."
    ),
    source_system=SourceSystem.splunk,
    required_scope="asset:read",
    request_model=GetAssetRequest,
    response_model=SplunkResultsResponse,
    view_model=AssetView,
    projector=_project,
    live=LiveContract(
        status="fixture",
        system="Splunk Enterprise Security, Asset and Identity framework",
        endpoint=("search/v2 job with '| inputlookup asset_lookup_by_str where key=\"<value>\"'"),
        auth="as search_siem",
        permission="read on the asset_lookup_by_str lookup",
        notes="Coordinates and MAC addresses are dropped by the projection.",
    ),
)
