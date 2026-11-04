from wf_peering.protocol import entries
from wf_peering.protocol.signing import Signer
from wf_peering.services import LedgerService
from wf_peering.settings import settings
from wf_peering.utils import netcheck
import asyncio, hashlib, json, pytest


@pytest.mark.parametrize("page,code", [
    ({"entries": [{"content": {"seq": 1}}]}, "RANGE_NO_PROGRESS"),
    ({"entries": [{"content": []}]}, "INVALID_RANGE"),
    ({"entries": "not-a-list"}, "INVALID_RANGE"),
    ({"entries": [{"content": {"seq": 3}}]}, "RANGE_NO_PROGRESS")
])
async def test_full_sync_stops_when_the_host_cannot_advance_the_range(fluid, monkeypatch, page, code):
    from fluid.exceptions import SyncFailure
    from fluid.utils import sync
    signer = Signer.generate()
    head = entries.head(2, "a" * 64, "b" * 64, entries.utc_now(), settings.host, 1, 1)
    signed = {"head": head, "key": signer.public_key, "signature": signer.sign(entries.HEAD_CONTEXT, head)}

    async def key(): return signer.public_key
    async def local(): return 1, "c" * 64
    async def ingest(*args): return "duplicate"
    async def get(url, path, *args): return 200, signed if path.endswith("/head") else page, {}

    monkeypatch.setattr(sync, "pinned_host_key", key)
    monkeypatch.setattr(sync, "ingest", ingest)
    monkeypatch.setattr(LedgerService, "head", local)
    monkeypatch.setattr(netcheck, "get_json", get)
    with pytest.raises(SyncFailure, match=code):
        await asyncio.wait_for(sync.FullSync._attempt(), timeout=1)


async def test_host_selected_reference_does_not_establish_independent_trust(fluid, monkeypatch):
    from fluid.utils import observe
    data = b"untrusted code"
    value = hashlib.sha256(data).hexdigest()
    record = {"id": "widget", "algorithm": "sha256", "hash": value, "url": "/widget.js",
              "reference": {"manifest": "https://raw.githubusercontent.com/example/ref/main/manifest.json"}}
    manifest = {"artifact": "widget", "algorithm": "sha256", "latest": "v1",
                "versions": [{"version": "v1", "sha256": value}]}

    async def get(*args): return {"status": 200, "body": data}
    async def reference(*args): return json.dumps(manifest).encode()

    monkeypatch.setattr(netcheck, "get", get)
    monkeypatch.setattr(netcheck, "reference", reference)
    monkeypatch.setattr(settings, "references", {})
    result = await observe.observe(record)
    assert result["status"] == "unreferenced" and result["reference"]["origin"] == "host-supplied"
    monkeypatch.setitem(settings.references, "widget", record["reference"]["manifest"])
    assert (await observe.observe(record))["status"] == "verified"


@pytest.mark.parametrize("versions,latest", [
    ([{"version": "v1", "sha256": "g" * 64}], "v1"),
    ([{"version": "v1", "sha256": "a" * 64}] * 2, "v1"),
    ([{"version": "v1", "sha256": "a" * 64}], "absent"),
    ([{"version": "v1", "sha256": "a" * 64}], [])
])
def test_malformed_references_are_rejected(versions, latest):
    from fluid.utils.observe import parse_manifest
    assert parse_manifest(json.dumps({"artifact": "widget", "versions": versions, "latest": latest}).encode()) is None


@pytest.mark.parametrize("data", [b'{"algorithm": ["sha256"]}', b'[' * 2000 + b']' * 2000])
def test_invalid_reference_types_and_depth_are_rejected(data):
    from fluid.utils.observe import parse_manifest
    assert parse_manifest(data) is None
