"""Live ``get_attack_technique`` against the public ATT&CK enterprise STIX bundle.

The bundle is one large JSON document with no per-object endpoint, so the adapter
downloads it once, caches it on disk, and indexes ``attack-pattern`` objects by their
ATT&CK external id. A revoked technique is returned with the object that replaces it,
resolved through the bundle's ``revoked-by`` relationships.

Given a ``fallback_bundle_path``, a failed download is served from that file instead,
and the adapter's ``kind`` becomes ``recorded`` so the run artifact says so. A cached
bundle is the real bundle and stays ``live``.
"""

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from pydantic import JsonValue

from alert_forensics.tools.adapter import ToolAdapter, UpstreamError
from alert_forensics.tools.definitions.get_attack_technique import (
    GET_ATTACK_TECHNIQUE,
    AttackTechniqueResponse,
    AttackTechniqueView,
    GetAttackTechniqueRequest,
)

ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
BUNDLE_FILENAME = "enterprise-attack.json"

StixObject = dict[str, Any]


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "alert-forensics" / "attack"


@dataclass(frozen=True)
class _Index:
    by_external_id: dict[str, StixObject]
    by_stix_id: dict[str, StixObject]
    revoked_by: dict[str, str]


def _external_id(obj: StixObject) -> str | None:
    for reference in obj.get("external_references", []):
        if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack":
            external_id = reference.get("external_id")
            return str(external_id) if external_id is not None else None
    return None


def _build_index(bundle: StixObject) -> _Index:
    by_external_id: dict[str, StixObject] = {}
    by_stix_id: dict[str, StixObject] = {}
    revoked_by: dict[str, str] = {}
    for obj in bundle["objects"]:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "attack-pattern":
            by_stix_id[str(obj["id"])] = obj
            external_id = _external_id(obj)
            if external_id is not None and external_id not in by_external_id:
                by_external_id[external_id] = obj
        elif obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_by[str(obj["source_ref"])] = str(obj["target_ref"])
    return _Index(by_external_id, by_stix_id, revoked_by)


def _parse_bundle(data: bytes, origin: str) -> StixObject:
    try:
        bundle = json.loads(data)
    except ValueError as exc:
        raise UpstreamError("upstream_error", f"ATT&CK bundle at {origin} is not JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise UpstreamError("upstream_error", f"ATT&CK bundle at {origin} is not a STIX bundle")
    if not isinstance(bundle.get("objects"), list):
        raise UpstreamError("upstream_error", f"ATT&CK bundle at {origin} has no objects")
    return bundle


class AttackStixAdapter(
    ToolAdapter[GetAttackTechniqueRequest, AttackTechniqueResponse, AttackTechniqueView]
):
    def __init__(
        self,
        cache_dir: Path | None = None,
        client: httpx.Client | None = None,
        bundle_url: str = ATTACK_BUNDLE_URL,
        bundle_path: Path | None = None,
        timeout: float = 120.0,
        fallback_bundle_path: Path | None = None,
    ) -> None:
        super().__init__(GET_ATTACK_TECHNIQUE)
        self.cache_dir = cache_dir or default_cache_dir()
        self.bundle_url = bundle_url
        self.bundle_path = bundle_path
        self.fallback_bundle_path = fallback_bundle_path
        self._client = client
        self._timeout = timeout
        self._index: _Index | None = None

    def fetch(self, request: GetAttackTechniqueRequest) -> JsonValue:
        index = self._ensure_index()
        technique = index.by_external_id.get(request.technique_id)
        if technique is None:
            raise UpstreamError(
                "not_found",
                f"{request.technique_id} is not a technique in the ATT&CK enterprise bundle",
            )
        superseded_by = None
        if technique.get("revoked"):
            replacement_id = index.revoked_by.get(str(technique["id"]))
            if replacement_id is not None:
                superseded_by = index.by_stix_id.get(replacement_id)
        return {
            "technique": copy.deepcopy(technique),
            "superseded_by": copy.deepcopy(superseded_by),
        }

    def _ensure_index(self) -> _Index:
        if self._index is None:
            self._index = _build_index(self._load_bundle())
        return self._index

    def _load_bundle(self) -> StixObject:
        if self.bundle_path is not None:
            return self._read_file(self.bundle_path)
        cached = self.cache_dir / BUNDLE_FILENAME
        if cached.exists():
            try:
                return _parse_bundle(cached.read_bytes(), str(cached))
            except UpstreamError:
                cached.unlink(missing_ok=True)
        try:
            data = self._download()
        except UpstreamError:
            if self.fallback_bundle_path is None:
                raise
            bundle = self._read_file(self.fallback_bundle_path)
            self.kind = "recorded"
            return bundle
        bundle = _parse_bundle(data, self.bundle_url)
        self._write_cache(cached, data)
        return bundle

    def _read_file(self, path: Path) -> StixObject:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise UpstreamError("upstream_error", f"cannot read ATT&CK bundle {path}") from exc
        return _parse_bundle(data, str(path))

    def _download(self) -> bytes:
        client = self._client or httpx.Client(timeout=self._timeout, follow_redirects=True)
        try:
            response = client.get(self.bundle_url)
        except (httpx.HTTPError, OSError) as exc:
            raise UpstreamError(
                "upstream_error", f"ATT&CK bundle download failed: {type(exc).__name__}"
            ) from exc
        if response.status_code != 200:
            raise UpstreamError(
                "upstream_error", f"ATT&CK bundle download returned HTTP {response.status_code}"
            )
        return response.content

    def _write_cache(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".part")
        tmp.write_bytes(data)
        os.replace(tmp, path)
