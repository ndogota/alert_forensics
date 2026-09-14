import json

import httpx
import pytest

from alert_forensics.tools import DEFINITIONS, UpstreamError
from alert_forensics.tools.live.virustotal import (
    VT_BASE_URL,
    VirusTotalAdapter,
    classify_indicator,
)
from conftest import load_recorded

REQUEST = DEFINITIONS["lookup_ioc"].request_model


@pytest.mark.parametrize(
    ("indicator", "kind", "path_id"),
    [
        ("203.0.113.7", "ip_address", "203.0.113.7"),
        ("2001:db8::1", "ip_address", "2001:db8::1"),
        ("never-seen.example", "domain", "never-seen.example"),
        ("Sub.Example.COM", "domain", "sub.example.com"),
        ("9e107d9d372bb6826bd81d3542a419d6", "file", "9e107d9d372bb6826bd81d3542a419d6"),
        (
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "file",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        ),
        (
            "3F5A9C1E7B2D4F6A8C0E1B3D5F7A9C2E4B6D8F0A1C3E5B7D9F1A3C5E7B9D1F3A",
            "file",
            "3f5a9c1e7b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f1a3c5e7b9d1f3a",
        ),
        (
            "https://relay.example.net/invoice.hta",
            "url",
            "aHR0cHM6Ly9yZWxheS5leGFtcGxlLm5ldC9pbnZvaWNlLmh0YQ",
        ),
    ],
)
def test_indicator_classification_is_deterministic(indicator, kind, path_id):
    assert classify_indicator(indicator) == (kind, path_id)


def test_unclassifiable_indicator_is_rejected():
    with pytest.raises(ValueError):
        classify_indicator("not an indicator at all")


def recorded_client(
    name: str, status: int, expect_path: str | None = None, calls: list | None = None
):
    body = load_recorded("virustotal", f"{name}.json")

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        assert request.method == "GET"
        assert request.headers["x-apikey"] == "test-key"
        assert "accept" in request.headers and "json" in request.headers["accept"]
        if expect_path is not None:
            assert request.url.path == expect_path
        return httpx.Response(status, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ip_lookup_hits_the_documented_endpoint_and_returns_the_envelope():
    calls: list[httpx.Request] = []
    adapter = VirusTotalAdapter(
        api_key="test-key",
        client=recorded_client("ip_address", 200, "/api/v3/ip_addresses/203.0.113.7", calls),
    )
    raw = adapter.fetch(REQUEST(indicator="203.0.113.7"))
    assert raw == load_recorded("virustotal", "ip_address.json")
    assert calls[0].url.host == "www.virustotal.com"
    assert str(calls[0].url).startswith(VT_BASE_URL)
    view = DEFINITIONS["lookup_ioc"].project(
        DEFINITIONS["lookup_ioc"].response_model.model_validate(raw)
    )
    assert view.detection_ratio == "0/94" and view.known


def test_file_lookup_reads_the_signature_and_excludes_unsupported_engines():
    sha = "3f5a9c1e7b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f1a3c5e7b9d1f3a"
    adapter = VirusTotalAdapter(
        api_key="test-key", client=recorded_client("file", 200, f"/api/v3/files/{sha}")
    )
    raw = adapter.fetch(REQUEST(indicator=sha))
    definition = DEFINITIONS["lookup_ioc"]
    view = definition.project(definition.response_model.model_validate(raw))
    assert view.indicator_type == "file"
    assert view.detection_ratio == "0/72"
    assert view.engines is not None and view.engines.not_analysed == 5
    assert view.context["signed"] is True
    assert view.context["signers"].startswith("Example Software Ltd")
    assert view.context["meaningful_name"] == "RemoteSupport.ClientSetup.exe"
    assert view.context["first_submission_at"] == "2026-08-29T10:40:00Z"
    assert "last_analysis_results" not in json.dumps(view.model_dump(mode="json"))


def test_url_lookup_uses_the_base64url_id():
    adapter = VirusTotalAdapter(
        api_key="test-key",
        client=recorded_client(
            "not_found", 404, "/api/v3/urls/aHR0cHM6Ly9yZWxheS5leGFtcGxlLm5ldC9pbnZvaWNlLmh0YQ"
        ),
    )
    raw = adapter.fetch(REQUEST(indicator="https://relay.example.net/invoice.hta"))
    assert raw["error"]["code"] == "NotFoundError"


def test_not_found_is_returned_as_a_response_not_raised():
    adapter = VirusTotalAdapter(api_key="test-key", client=recorded_client("not_found", 404))
    raw = adapter.fetch(REQUEST(indicator="never-seen.example"))
    assert raw == load_recorded("virustotal", "not_found.json")


@pytest.mark.parametrize(
    ("name", "status", "fragment"),
    [
        ("wrong_credentials", 401, "WrongCredentialsError"),
        ("quota_exceeded", 429, "QuotaExceededError"),
    ],
)
def test_other_api_errors_raise_upstream_error(name, status, fragment):
    adapter = VirusTotalAdapter(api_key="test-key", client=recorded_client(name, status))
    with pytest.raises(UpstreamError) as info:
        adapter.fetch(REQUEST(indicator="203.0.113.7"))
    assert info.value.kind == "upstream_error"
    assert fragment in info.value.detail and str(status) in info.value.detail


def test_transport_failures_raise_upstream_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    adapter = VirusTotalAdapter(
        api_key="test-key", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(UpstreamError) as info:
        adapter.fetch(REQUEST(indicator="203.0.113.7"))
    assert info.value.kind == "upstream_error"

    def not_json(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>maintenance</html>")

    adapter = VirusTotalAdapter(
        api_key="test-key", client=httpx.Client(transport=httpx.MockTransport(not_json))
    )
    with pytest.raises(UpstreamError):
        adapter.fetch(REQUEST(indicator="203.0.113.7"))


def test_the_adapter_needs_a_key():
    with pytest.raises(ValueError):
        VirusTotalAdapter(
            api_key="",
            client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
        )


def test_the_api_key_never_appears_in_errors():
    adapter = VirusTotalAdapter(
        api_key="test-key", client=recorded_client("wrong_credentials", 401)
    )
    with pytest.raises(UpstreamError) as info:
        adapter.fetch(REQUEST(indicator="203.0.113.7"))
    assert "test-key" not in info.value.detail
