import json

import httpx
import pytest

from alert_forensics.tools import DEFINITIONS, UpstreamError
from alert_forensics.tools.live.attack import ATTACK_BUNDLE_URL, AttackStixAdapter
from conftest import RECORDED_DIR, load_recorded

REQUEST = DEFINITIONS["get_attack_technique"].request_model
EXCERPT = RECORDED_DIR / "attack" / "enterprise-attack.excerpt.json"


def bundle_client(calls: list | None = None) -> httpx.Client:
    body = EXCERPT.read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        assert request.method == "GET"
        assert str(request.url) == ATTACK_BUNDLE_URL
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_bundle_is_downloaded_once_and_cached_on_disk(tmp_path):
    calls: list[httpx.Request] = []
    adapter = AttackStixAdapter(cache_dir=tmp_path, client=bundle_client(calls))
    raw = adapter.fetch(REQUEST(technique_id="T1110.003"))
    assert raw["technique"]["name"] == "Password Spraying"
    assert raw["superseded_by"] is None
    adapter.fetch(REQUEST(technique_id="T1078.004"))
    assert len(calls) == 1
    cached = tmp_path / "enterprise-attack.json"
    assert cached.exists()
    assert json.loads(cached.read_bytes()) == load_recorded(
        "attack", "enterprise-attack.excerpt.json"
    )
    # A second adapter over the same cache never touches the network.
    offline = AttackStixAdapter(cache_dir=tmp_path, client=bundle_client(calls))
    assert (
        offline.fetch(REQUEST(technique_id="T1219"))["technique"]["name"] == "Remote Access Tools"
    )
    assert len(calls) == 1


def test_a_local_bundle_path_needs_no_client_at_all(tmp_path):
    adapter = AttackStixAdapter(cache_dir=tmp_path, bundle_path=EXCERPT)
    raw = adapter.fetch(REQUEST(technique_id="T1558.003"))
    assert raw["technique"]["external_references"][0]["external_id"] == "T1558.003"
    assert raw["technique"]["kill_chain_phases"] == [
        {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
    ]


def test_the_raw_is_the_verbatim_stix_object(tmp_path):
    adapter = AttackStixAdapter(cache_dir=tmp_path, bundle_path=EXCERPT)
    raw = adapter.fetch(REQUEST(technique_id="T1110.003"))
    bundle = load_recorded("attack", "enterprise-attack.excerpt.json")
    verbatim = next(
        o
        for o in bundle["objects"]
        if o["type"] == "attack-pattern"
        and o["id"] == "attack-pattern--692074ae-bb62-4a5e-a735-02cb6bde458c"
    )
    assert raw["technique"] == verbatim


def test_projection_of_a_real_object(tmp_path):
    adapter = AttackStixAdapter(cache_dir=tmp_path, bundle_path=EXCERPT)
    definition = DEFINITIONS["get_attack_technique"]
    raw = adapter.fetch(REQUEST(technique_id="T1219"))
    view = definition.project(definition.response_model.model_validate(raw))
    assert view.technique_id == "T1219"
    assert view.name == "Remote Access Tools"
    assert view.tactics == ["command-and-control"]
    assert view.is_subtechnique is False
    assert "(Citation:" not in view.description and view.description
    assert "Windows" in view.platforms
    assert view.url == "https://attack.mitre.org/techniques/T1219"


def test_revoked_technique_names_its_replacement(tmp_path):
    adapter = AttackStixAdapter(cache_dir=tmp_path, bundle_path=EXCERPT)
    raw = adapter.fetch(REQUEST(technique_id="T1066"))
    assert raw["technique"]["revoked"] is True
    assert raw["superseded_by"]["name"] == "Indicator Removal from Tools"
    definition = DEFINITIONS["get_attack_technique"]
    view = definition.project(definition.response_model.model_validate(raw))
    assert view.revoked is True
    assert view.superseded_by is not None
    assert view.superseded_by.technique_id == "T1027.005"


def test_unknown_id_is_not_found(tmp_path):
    adapter = AttackStixAdapter(cache_dir=tmp_path, bundle_path=EXCERPT)
    with pytest.raises(UpstreamError) as info:
        adapter.fetch(REQUEST(technique_id="T9999"))
    assert info.value.kind == "not_found"
    assert "T9999" in info.value.detail


def test_download_failures_raise_upstream_error(tmp_path):
    def failing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    adapter = AttackStixAdapter(
        cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(failing))
    )
    with pytest.raises(UpstreamError) as info:
        adapter.fetch(REQUEST(technique_id="T1110"))
    assert info.value.kind == "upstream_error" and "503" in info.value.detail
    assert not (tmp_path / "enterprise-attack.json").exists()


def test_a_corrupt_cache_is_not_trusted(tmp_path):
    (tmp_path / "enterprise-attack.json").write_text("{not json")
    calls: list[httpx.Request] = []
    adapter = AttackStixAdapter(cache_dir=tmp_path, client=bundle_client(calls))
    assert adapter.fetch(REQUEST(technique_id="T1110"))["technique"]["name"] == "Brute Force"
    assert len(calls) == 1
