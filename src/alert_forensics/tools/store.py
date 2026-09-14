"""Out-of-context storage for raw tool responses.

A record carries ``raw_response_ref`` and ``raw_response_sha256``; the store is what the
ref points into. Two implementations: in memory for tests and scripted runs, a directory
for run artifacts. Both verify the hash on read when asked, so a tampered artifact is
detected rather than replayed.
"""

import json
import re
from pathlib import Path
from typing import Protocol

from pydantic import JsonValue

from alert_forensics.contracts import hash_raw_response
from alert_forensics.contracts._base import ContractModel


class RawIntegrityError(Exception):
    """The stored raw does not hash to what the record says it should."""


class StoredRaw(ContractModel):
    ref: str
    sha256: str


class RawResponseStore(Protocol):
    def put(self, investigation_id: str, tool_call_id: str, raw: JsonValue) -> StoredRaw: ...

    def get(self, ref: str, expected_sha256: str | None = None) -> JsonValue: ...


_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.:]*$")


def _segment(value: str, what: str) -> str:
    if not _SAFE_SEGMENT.match(value) or value in {".", ".."}:
        raise ValueError(f"{what} {value!r} is not a safe path segment")
    return value


def make_ref(investigation_id: str, tool_call_id: str) -> str:
    investigation = _segment(investigation_id, "investigation_id")
    call = _segment(tool_call_id, "tool_call_id")
    return f"{investigation}/{call}.json"


def _split_ref(ref: str) -> tuple[str, str]:
    parts = ref.split("/")
    if len(parts) != 2 or not parts[1].endswith(".json"):
        raise ValueError(f"malformed raw response ref {ref!r}")
    return _segment(parts[0], "investigation_id"), _segment(parts[1][:-5], "tool_call_id")


def _verify(raw: JsonValue, expected_sha256: str | None, ref: str) -> JsonValue:
    if expected_sha256 is not None and hash_raw_response(raw) != expected_sha256:
        raise RawIntegrityError(f"raw response {ref} does not match its recorded sha256")
    return raw


class InMemoryRawStore:
    def __init__(self) -> None:
        self._items: dict[str, JsonValue] = {}

    def put(self, investigation_id: str, tool_call_id: str, raw: JsonValue) -> StoredRaw:
        ref = make_ref(investigation_id, tool_call_id)
        if ref in self._items:
            raise FileExistsError(f"raw response {ref} already stored")
        self._items[ref] = json.loads(json.dumps(raw))
        return StoredRaw(ref=ref, sha256=hash_raw_response(raw))

    def get(self, ref: str, expected_sha256: str | None = None) -> JsonValue:
        _split_ref(ref)
        if ref not in self._items:
            raise KeyError(ref)
        return _verify(json.loads(json.dumps(self._items[ref])), expected_sha256, ref)


class DirectoryRawStore:
    """One JSON file per call under ``root/<investigation_id>/<tool_call_id>.json``."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, ref: str) -> Path:
        investigation_id, tool_call_id = _split_ref(ref)
        return self.root / investigation_id / f"{tool_call_id}.json"

    def put(self, investigation_id: str, tool_call_id: str, raw: JsonValue) -> StoredRaw:
        ref = make_ref(investigation_id, tool_call_id)
        path = self._path(ref)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as handle:
            json.dump(raw, handle, ensure_ascii=False, sort_keys=True, indent=1)
        return StoredRaw(ref=ref, sha256=hash_raw_response(raw))

    def get(self, ref: str, expected_sha256: str | None = None) -> JsonValue:
        path = self._path(ref)
        if not path.exists():
            raise KeyError(ref)
        raw: JsonValue = json.loads(path.read_text(encoding="utf-8"))
        return _verify(raw, expected_sha256, ref)
