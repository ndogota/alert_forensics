"""Live ``lookup_ioc`` against the VirusTotal API v3."""

import httpx
from pydantic import JsonValue

from alert_forensics.tools.adapter import ToolAdapter, UpstreamError
from alert_forensics.tools.definitions.lookup_ioc import (
    LOOKUP_IOC,
    IndicatorType,
    IocReading,
    LookupIocRequest,
    VirusTotalResponse,
    classify_indicator,
)

VT_BASE_URL = "https://www.virustotal.com/api/v3"

_COLLECTIONS: dict[IndicatorType, str] = {
    "ip_address": "ip_addresses",
    "domain": "domains",
    "file": "files",
    "url": "urls",
}

__all__ = ["VT_BASE_URL", "VirusTotalAdapter", "classify_indicator"]


class VirusTotalAdapter(ToolAdapter[LookupIocRequest, VirusTotalResponse, IocReading]):
    """``GET {base}/{collection}/{id}`` with the key in ``x-apikey``.

    A 200 is the object; a 404 ``NotFoundError`` is returned as a response because an
    indicator unknown to VirusTotal is a reading. Anything else raises ``UpstreamError``
    and the message never includes the key.
    """

    def __init__(
        self,
        api_key: str,
        client: httpx.Client | None = None,
        base_url: str = VT_BASE_URL,
        timeout: float = 20.0,
    ) -> None:
        if not api_key:
            raise ValueError("a VirusTotal API key is required (set VIRUSTOTAL_API_KEY)")
        super().__init__(LOOKUP_IOC)
        self._api_key = api_key
        self._client = client or httpx.Client(timeout=timeout)
        self._base_url = base_url.rstrip("/")

    def fetch(self, request: LookupIocRequest) -> JsonValue:
        kind, object_id = classify_indicator(request.indicator)
        url = f"{self._base_url}/{_COLLECTIONS[kind]}/{object_id}"
        try:
            response = self._client.get(
                url, headers={"x-apikey": self._api_key, "accept": "application/json"}
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(
                "upstream_error", f"VirusTotal request failed: {type(exc).__name__}"
            ) from exc
        try:
            body: JsonValue = response.json()
        except ValueError as exc:
            raise UpstreamError(
                "upstream_error",
                f"VirusTotal returned HTTP {response.status_code} with a non-JSON body",
            ) from exc
        code = _error_code(body)
        if response.status_code == 200 or (response.status_code == 404 and code == "NotFoundError"):
            return body
        raise UpstreamError(
            "upstream_error",
            f"VirusTotal returned HTTP {response.status_code} {code or ''}".rstrip(),
        )


def _error_code(body: JsonValue) -> str | None:
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            return str(code) if code is not None else None
    return None
