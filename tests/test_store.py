import json

import pytest

from alert_forensics.contracts import hash_raw_response
from alert_forensics.tools import DirectoryRawStore, InMemoryRawStore, RawIntegrityError

RAW = {"data": {"id": "203.0.113.7", "attributes": {"whois": "phone: +31 20 000 0000", "é": 1}}}


@pytest.fixture(params=["memory", "directory"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryRawStore()
    return DirectoryRawStore(tmp_path / "raw")


def test_put_returns_ref_and_sha_and_get_returns_the_same_json(store):
    stored = store.put("inv-1", "tc-1", RAW)
    assert stored.ref == "inv-1/tc-1.json"
    assert stored.sha256 == hash_raw_response(RAW)
    assert store.get(stored.ref) == RAW
    assert store.get(stored.ref, expected_sha256=stored.sha256) == RAW


def test_get_verifies_integrity(store):
    stored = store.put("inv-1", "tc-1", RAW)
    with pytest.raises(RawIntegrityError):
        store.get(stored.ref, expected_sha256="0" * 64)
    with pytest.raises(KeyError):
        store.get("inv-1/missing.json")


def test_a_ref_is_written_once(store):
    store.put("inv-1", "tc-1", RAW)
    with pytest.raises(FileExistsError):
        store.put("inv-1", "tc-1", {"other": True})


def test_directory_store_writes_one_file_per_call(tmp_path):
    root = tmp_path / "raw"
    store = DirectoryRawStore(root)
    stored = store.put("inv-1", "tc-1", RAW)
    path = root / "inv-1" / "tc-1.json"
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8")) == RAW
    # A fresh store over the same directory reads it back and detects tampering.
    again = DirectoryRawStore(root)
    assert again.get(stored.ref, expected_sha256=stored.sha256) == RAW
    path.write_text(json.dumps({"tampered": True}))
    with pytest.raises(RawIntegrityError):
        again.get(stored.ref, expected_sha256=stored.sha256)


def test_refs_cannot_escape_the_store(tmp_path):
    store = DirectoryRawStore(tmp_path / "raw")
    for bad_id in ("../x", "a/b", "", "..", ".x"):
        with pytest.raises(ValueError):
            store.put("inv-1", bad_id, RAW)
    with pytest.raises(ValueError):
        store.put("../inv", "tc-1", RAW)
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")
