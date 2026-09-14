"""``lookup_ioc``: VirusTotal v3. The projection is the reading the spec promises: engine
counters and the community reputation are read by code, and the model receives the
reading, not the raw temptation of engine-by-engine verdicts."""

import base64
import ipaddress
import re
from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import (
    LiveContract,
    ToolDefinition,
    ToolRequest,
    ToolResponse,
    ToolView,
)
from alert_forensics.tools.definitions._common import epoch_to_iso, optional_int, optional_str

IndicatorType = Literal["ip_address", "domain", "file", "url"]

_HEX_HASH = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def classify_indicator(indicator: str) -> tuple[IndicatorType, str]:
    """Deterministic parsing of an indicator into its VirusTotal collection and object id.

    IPs are looked up as given, hashes and domains lowercased, URLs as the unpadded
    base64url of the URL, which is the id VirusTotal assigns to a URL object.
    """
    text = indicator.strip()
    if "://" in text:
        return "url", base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    try:
        return "ip_address", str(ipaddress.ip_address(text))
    except ValueError:
        pass
    lowered = text.lower()
    if _HEX_HASH.match(lowered):
        return "file", lowered
    if _DOMAIN.match(lowered):
        return "domain", lowered
    raise ValueError(f"{indicator!r} is not an IP address, domain, URL or file hash")


class LookupIocRequest(ToolRequest):
    indicator: str = Field(
        min_length=1, description="An IP address, domain, URL, or MD5/SHA-1/SHA-256 hash."
    )

    @field_validator("indicator")
    @classmethod
    def _classifiable(cls, value: str) -> str:
        classify_indicator(value)
        return value


class VtObject(ToolResponse):
    id: str
    type: str
    attributes: dict[str, JsonValue]


class VtError(ToolResponse):
    code: str
    message: str | None = None


class VirusTotalResponse(ToolResponse):
    """The JSON:API envelope: ``data`` on success, ``error`` on a 404 ``NotFoundError``.
    Other error codes never become a response; the adapter raises on them."""

    data: VtObject | None = None
    error: VtError | None = None

    @model_validator(mode="after")
    def _data_or_not_found(self) -> "VirusTotalResponse":
        if (self.data is None) == (self.error is None):
            raise ValueError("a VirusTotal response carries exactly one of data or error")
        if self.error is not None and self.error.code != "NotFoundError":
            raise ValueError(f"VirusTotal error {self.error.code} is not a response")
        return self


class EngineCounters(ToolView):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    verdicts: int
    """Engines that returned a verdict: the denominator of the detection ratio."""
    not_analysed: int
    """Timeouts, failures and unsupported types. Not a verdict either way."""


class Reputation(ToolView):
    score: int
    reading: str


class IocReading(ToolView):
    indicator: str
    indicator_type: str
    known: bool
    engines: EngineCounters | None
    detection_ratio: str | None
    reputation: Reputation | None
    last_analysis_at: str | None
    tags: list[str]
    context: dict[str, JsonValue]
    note: str


_VERDICT_KEYS = ("malicious", "suspicious", "harmless", "undetected")


def _counters(stats: JsonValue) -> EngineCounters | None:
    if not isinstance(stats, dict):
        return None
    counts = {k: optional_int(stats.get(k)) or 0 for k in _VERDICT_KEYS}
    other = sum(optional_int(v) or 0 for k, v in stats.items() if k not in _VERDICT_KEYS)
    return EngineCounters(**counts, verdicts=sum(counts.values()), not_analysed=other)


def _reputation(score: JsonValue) -> Reputation | None:
    value = optional_int(score)
    if value is None:
        return None
    if value == 0:
        reading = "no community signal: zero means nobody voted, not clean"
    elif value < 0:
        reading = "community votes lean malicious"
    else:
        reading = "community votes lean benign"
    return Reputation(score=value, reading=reading)


def _context(kind: str, attributes: dict[str, JsonValue]) -> dict[str, JsonValue]:
    if kind == "ip_address":
        return {
            "country": optional_str(attributes.get("country")),
            "as_owner": optional_str(attributes.get("as_owner")),
            "asn": optional_int(attributes.get("asn")),
            "network": optional_str(attributes.get("network")),
        }
    if kind == "domain":
        return {
            "registrar": optional_str(attributes.get("registrar")),
            "created_at": epoch_to_iso(attributes.get("creation_date")),
        }
    if kind == "file":
        signature = attributes.get("signature_info")
        signature = signature if isinstance(signature, dict) else {}
        verified = optional_str(signature.get("verified"))
        return {
            "meaningful_name": optional_str(attributes.get("meaningful_name")),
            "type_description": optional_str(attributes.get("type_description")),
            "size": optional_int(attributes.get("size")),
            "signed": None if verified is None else verified.lower() == "signed",
            "signers": optional_str(signature.get("signers")),
            "first_submission_at": epoch_to_iso(attributes.get("first_submission_date")),
            "times_submitted": optional_int(attributes.get("times_submitted")),
        }
    if kind == "url":
        return {
            "final_url": optional_str(attributes.get("last_final_url")),
            "title": optional_str(attributes.get("title")),
        }
    return {}


def _indicator_from(response: VirusTotalResponse) -> str:
    """Without the request, the best name for the indicator the response has: the object
    id, or the quoted name in a not-found message."""
    if response.data is not None:
        return response.data.id
    message = (response.error.message if response.error else None) or ""
    quoted = re.search(r'"([^"]+)"', message)
    return quoted.group(1) if quoted else "unknown"


def _project(response: VirusTotalResponse, request: LookupIocRequest | None) -> IocReading:
    indicator = request.indicator if request is not None else _indicator_from(response)
    try:
        guessed: str = classify_indicator(indicator)[0]
    except ValueError:
        guessed = "unknown"
    if response.data is None:
        return IocReading(
            indicator=indicator,
            indicator_type=guessed,
            known=False,
            engines=None,
            detection_ratio=None,
            reputation=None,
            last_analysis_at=None,
            tags=[],
            context={},
            note=(
                "VirusTotal has no record of this indicator. Absence of a record is not a "
                "clean verdict; it means nobody submitted it."
            ),
        )
    attributes = response.data.attributes
    engines = _counters(attributes.get("last_analysis_stats"))
    tags = attributes.get("tags")
    return IocReading(
        indicator=indicator,
        indicator_type=response.data.type,
        known=True,
        engines=engines,
        detection_ratio=f"{engines.malicious}/{engines.verdicts}" if engines else None,
        reputation=_reputation(attributes.get("reputation")),
        last_analysis_at=epoch_to_iso(attributes.get("last_analysis_date")),
        tags=[str(t) for t in tags] if isinstance(tags, list) else [],
        context=_context(response.data.type, attributes),
        note=(
            "Engine counters are how many engines returned each verdict in the last "
            "analysis. Reputation is the signed sum of community votes; zero means unvoted."
        ),
    )


LOOKUP_IOC = ToolDefinition(
    name="lookup_ioc",
    description=(
        "Look up an IP address, domain, URL or file hash on VirusTotal. Returns the engine "
        "verdict counters as a detection ratio, the community reputation with its reading, "
        "and type-specific context such as AS owner or code signer."
    ),
    source_system=SourceSystem.virustotal,
    required_scope="ioc:lookup",
    request_model=LookupIocRequest,
    response_model=VirusTotalResponse,
    view_model=IocReading,
    projector=_project,
    live=LiveContract(
        status="live",
        system="VirusTotal API v3",
        endpoint=("GET https://www.virustotal.com/api/v3/{ip_addresses|domains|files|urls}/{id}"),
        auth="x-apikey header; a free public key works",
        permission="VirusTotal API key (VIRUSTOTAL_API_KEY)",
        notes=(
            "Free keys are limited to 4 requests a minute and 500 a day. A 404 NotFoundError "
            "is a reading, not a failure. Engine-by-engine results and whois are dropped."
        ),
    ),
)
