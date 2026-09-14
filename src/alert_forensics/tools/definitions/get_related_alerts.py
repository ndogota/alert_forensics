"""``get_related_alerts``: Microsoft Graph ``security/alerts_v2`` filtered on a pivot."""

from datetime import UTC

from pydantic import Field, model_validator

from alert_forensics.contracts import Alert, SourceSystem
from alert_forensics.tools.adapter import (
    LiveContract,
    ToolDefinition,
    ToolRequest,
    ToolResponse,
    ToolView,
)

MAX_ALERTS = 25


class GetRelatedAlertsRequest(ToolRequest):
    user_principal_name: str | None = None
    device_name: str | None = None
    incident_id: str | None = None
    hours: int = Field(default=72, ge=1, le=720, description="Look-back window.")

    @model_validator(mode="after")
    def _at_least_one_pivot(self) -> "GetRelatedAlertsRequest":
        if not any((self.user_principal_name, self.device_name, self.incident_id)):
            raise ValueError("give at least one of user_principal_name, device_name, incident_id")
        return self


class RelatedAlertsResponse(ToolResponse):
    """The Graph collection envelope; ``@odata.context`` and paging links are tolerated."""

    value: list[Alert] = Field(default_factory=list)


class AlertSummary(ToolView):
    id: str
    title: str
    severity: str
    status: str
    category: str | None
    classification: str | None
    determination: str | None
    created_date_time: str
    detection_source: str | None
    incident_id: str | None
    mitre_techniques: list[str]


class RelatedAlertsView(ToolView):
    count: int
    alerts: list[AlertSummary]
    truncated: bool


def _summary(alert: Alert) -> AlertSummary:
    return AlertSummary(
        id=alert.id,
        title=alert.title,
        severity=alert.severity.value,
        status=alert.status.value,
        category=alert.category,
        classification=alert.classification,
        determination=alert.determination,
        created_date_time=alert.created_date_time.astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        detection_source=alert.detection_source,
        incident_id=alert.incident_id,
        mitre_techniques=list(alert.mitre_techniques),
    )


def _project(
    response: RelatedAlertsResponse, request: GetRelatedAlertsRequest | None
) -> RelatedAlertsView:
    return RelatedAlertsView(
        count=len(response.value),
        alerts=[_summary(a) for a in response.value[:MAX_ALERTS]],
        truncated=len(response.value) > MAX_ALERTS,
    )


GET_RELATED_ALERTS = ToolDefinition(
    name="get_related_alerts",
    description=(
        "List other security alerts in the look-back window for the same user, device or "
        "incident, with their severity, status and prior classification."
    ),
    source_system=SourceSystem.graph_security,
    required_scope="alerts:read",
    request_model=GetRelatedAlertsRequest,
    response_model=RelatedAlertsResponse,
    view_model=RelatedAlertsView,
    projector=_project,
    live=LiveContract(
        status="fixture",
        system="Microsoft Graph security API",
        endpoint="GET https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=...",
        auth="OAuth 2.0 bearer token from Entra ID",
        permission="SecurityAlert.Read.All",
        notes=(
            "The adapter builds the OData filter: createdDateTime ge <now - hours> and "
            "incidentId eq '<id>' or evidence/any(e: ...) on the user or device."
        ),
    ),
)
