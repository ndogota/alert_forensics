"""Alert contract, following the Microsoft Graph ``security.alert`` v2 shape.

Field names are snake_case in Python and camelCase on the wire. Unknown fields are kept
so a payload from a real tenant survives an archive-and-replay round-trip untouched.
"""

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    StringConstraints,
    Tag,
)
from pydantic.alias_generators import to_camel

MitreTechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
"""An ATT&CK technique id such as ``T1110`` or a sub-technique such as ``T1110.003``."""


class GraphModel(BaseModel):
    """Base for Graph-shaped objects: aliased to camelCase, unknown fields preserved."""

    model_config = ConfigDict(
        frozen=True,
        extra="allow",
        alias_generator=to_camel,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    def to_wire(self) -> dict[str, Any]:
        """Archival form: only the keys the source provided, in wire (camelCase) names.

        Defaults we never received (``severity="unknown"``, empty ``roles``) are not
        emitted, so an archived alert does not gain fields it never had.
        """
        return self.model_dump(mode="json", by_alias=True, exclude_unset=True)


class AlertSeverity(StrEnum):
    unknown = "unknown"
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    unknown_future_value = "unknownFutureValue"


class AlertStatus(StrEnum):
    unknown = "unknown"
    new = "new"
    in_progress = "inProgress"
    resolved = "resolved"
    unknown_future_value = "unknownFutureValue"


class UserAccount(GraphModel):
    account_name: str | None = None
    domain_name: str | None = None
    user_principal_name: str | None = None
    user_sid: str | None = None
    azure_ad_user_id: str | None = None
    display_name: str | None = None


class FileDetails(GraphModel):
    file_name: str | None = None
    file_path: str | None = None
    file_size: int | None = None
    file_publisher: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    issuer: str | None = None
    signer: str | None = None


class AlertEvidenceBase(GraphModel):
    """Fields common to every ``alertEvidence`` subtype."""

    odata_type: str = Field(alias="@odata.type")
    created_date_time: AwareDatetime | None = None
    verdict: str | None = None
    remediation_status: str | None = None
    roles: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class UserEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.userEvidence"] = Field(alias="@odata.type")
    user_account: UserAccount | None = None


class DeviceEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.deviceEvidence"] = Field(alias="@odata.type")
    device_dns_name: str | None = None
    mde_device_id: str | None = None
    azure_ad_device_id: str | None = None
    os_platform: str | None = None
    health_status: str | None = None
    risk_score: str | None = None
    rbac_group_name: str | None = None


class IpEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.ipEvidence"] = Field(alias="@odata.type")
    ip_address: str | None = None
    country_letter_code: str | None = None


class ProcessEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.processEvidence"] = Field(alias="@odata.type")
    process_id: int | None = None
    parent_process_id: int | None = None
    process_command_line: str | None = None
    process_creation_date_time: AwareDatetime | None = None
    parent_process_creation_date_time: AwareDatetime | None = None
    image_file: FileDetails | None = None
    parent_process_image_file: FileDetails | None = None
    user_account: UserAccount | None = None
    detection_status: str | None = None
    mde_device_id: str | None = None


class FileEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.fileEvidence"] = Field(alias="@odata.type")
    file_details: FileDetails | None = None
    detection_status: str | None = None
    mde_device_id: str | None = None


class UrlEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.urlEvidence"] = Field(alias="@odata.type")
    url: str | None = None


class MailboxEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.mailboxEvidence"] = Field(alias="@odata.type")
    display_name: str | None = None
    primary_address: str | None = None
    user_account: UserAccount | None = None


class CloudApplicationEvidence(AlertEvidenceBase):
    odata_type: Literal["#microsoft.graph.security.cloudApplicationEvidence"] = Field(
        alias="@odata.type"
    )
    app_id: int | None = None
    display_name: str | None = None
    instance_id: int | None = None
    instance_name: str | None = None
    saas_app_id: int | None = None


class UnknownEvidence(AlertEvidenceBase):
    """Fallback for any ``@odata.type`` we do not model. Keeps the type and every field."""


_EVIDENCE_TAGS: dict[str, str] = {
    "#microsoft.graph.security.userEvidence": "user",
    "#microsoft.graph.security.deviceEvidence": "device",
    "#microsoft.graph.security.ipEvidence": "ip",
    "#microsoft.graph.security.processEvidence": "process",
    "#microsoft.graph.security.fileEvidence": "file",
    "#microsoft.graph.security.urlEvidence": "url",
    "#microsoft.graph.security.mailboxEvidence": "mailbox",
    "#microsoft.graph.security.cloudApplicationEvidence": "cloud_application",
}


def _evidence_tag(value: Any) -> str:
    """Pick the union member from ``@odata.type``; anything unmodelled goes to ``unknown``."""
    if isinstance(value, dict):
        raw = value.get("@odata.type", value.get("odata_type"))
    else:
        raw = getattr(value, "odata_type", None)
    return _EVIDENCE_TAGS.get(raw, "unknown") if isinstance(raw, str) else "unknown"


AlertEvidence = Annotated[
    Annotated[UserEvidence, Tag("user")]
    | Annotated[DeviceEvidence, Tag("device")]
    | Annotated[IpEvidence, Tag("ip")]
    | Annotated[ProcessEvidence, Tag("process")]
    | Annotated[FileEvidence, Tag("file")]
    | Annotated[UrlEvidence, Tag("url")]
    | Annotated[MailboxEvidence, Tag("mailbox")]
    | Annotated[CloudApplicationEvidence, Tag("cloud_application")]
    | Annotated[UnknownEvidence, Tag("unknown")],
    Discriminator(_evidence_tag),
]
"""Polymorphic ``alertEvidence`` discriminated by ``@odata.type`` with an unknown fallback."""


class Alert(GraphModel):
    """A Microsoft Graph ``security.alert`` v2 object, minimally modelled."""

    id: str
    title: str
    description: str | None = None
    severity: AlertSeverity = AlertSeverity.unknown
    status: AlertStatus = AlertStatus.unknown
    category: str | None = None
    classification: str | None = None
    determination: str | None = None
    created_date_time: AwareDatetime
    last_update_date_time: AwareDatetime | None = None
    detection_source: str | None = None
    service_source: str | None = None
    provider_alert_id: str | None = None
    tenant_id: str | None = None
    incident_id: str | None = None
    mitre_techniques: list[MitreTechniqueId] = Field(default_factory=list)
    evidence: list[AlertEvidence] = Field(default_factory=list)
