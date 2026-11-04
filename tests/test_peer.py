from sqlalchemy import select
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
import asyncio, datetime, hashlib, importlib.util, json, os, pathlib, pytest, ssl, sys

HOST = os.environ["PEERING_TEST_HOST"]
PORT = int(HOST.rsplit(":", 1)[1])
STATE = {}


def _pki(tmp):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "peering test ca")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=2))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))

    def leaf(name, start, end, issuer_key=ca_key, issuer=ca_name):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(start).not_valid_after(end)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(issuer_key, hashes.SHA256()))
        cert_path, key_path = tmp / f"{name}-{start.timestamp()}.pem", tmp / f"{name}-{start.timestamp()}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        return cert_path, key_path

    ca_path = tmp / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    self_key = ec.generate_private_key(ec.SECP256R1())
    self_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "peer.test")])
    return ca_path, leaf, (self_key, self_name), now


async def conflicts(kind=None):
    from wf_peering.services import ConflictService
    return [item for item in await ConflictService.open() if kind is None or item["kind"] == kind]


async def test_full_sync_replicates_verifies_and_pins_the_host_key(host, client):
    from fluid.utils.sync import FullSync
    from wf_peering.services import StateService, LedgerService
    result = await FullSync.run("daily", "2026-10-08")
    assert result["status"] == "success", result
    assert result["to_seq"] == 2 and result["local_root"] == result["host_root"]
    assert await StateService.get("host_key") == host.signer.public_key
    assert (await LedgerService.head())[1] == host.items[-1]["hash"]

    integrity = (await client.get("/api/v1/integrity")).json()
    assert integrity["source"] == "host-ledger"
    assert integrity["groups"][0]["records"][0]["record"]["id"] == "users_e2ee"


async def test_transient_failures_are_retried(host):
    from fluid.utils.sync import FullSync
    host.append("peering:test", { "n": 3 })
    host.fail_head = 1
    result = await FullSync.run("full")
    assert result["status"] == "success" and result["attempts"] == 2 and result["to_seq"] == 3


async def test_incremental_replication_over_the_websocket(host):
    from fluid.utils.sync import HostLink
    from wf_peering.services import LedgerService
    HostLink.ensure()
    for _ in range(100):
        if HostLink.snapshot().get("state") == "connected" and host.sockets: break
        await asyncio.sleep(0.05)
    assert HostLink.snapshot()["state"] == "connected", HostLink.snapshot()
    item = host.append("peering:test", { "n": 4 })
    await host.push(item)
    for _ in range(100):
        if (await LedgerService.head())[0] == 4: break
        await asyncio.sleep(0.05)
    assert (await LedgerService.head())[0] == 4
    HostLink.stop()
    await asyncio.sleep(0.1)


async def test_checkpoint_follows_the_sync_state():
    from wf_peering.services import CheckpointService
    verified = await CheckpointService.compute(day="2026-10-08")
    assert verified["status"] == "verified" and verified["content"]["ledger"]["size"] == 2
    assert verified["content"]["sync"]["status"] == "verified"
    stale = await CheckpointService.compute(day="2026-10-09")
    assert stale["status"] == "stale" and stale["content"]["ledger"]["size"] == 3
    assert stale["content"]["prev"] == verified["hash"]


async def test_schema_mismatch_fails_without_retry(host):
    from fluid.utils.sync import FullSync
    host.schema = 2
    try:
        result = await FullSync.run("full")
    finally:
        host.schema = 1
    assert result["status"] == "failed" and result["error"] == "SCHEMA_MISMATCH" and result["attempts"] == 1


async def test_rewritten_history_is_detected_as_equivocation(host):
    from fluid.utils.sync import FullSync
    from wf_peering.services import LedgerService
    snapshot = list(host.items)
    host.rewrite(3, { "n": "rewritten" })
    host.append("peering:test", { "n": 5 })
    try:
        result = await FullSync.run("full")
    finally:
        host.items = snapshot
    assert result["status"] == "failed" and result["error"] == "FORK"
    found = await conflicts("host-equivocation")
    assert found and found[0]["severity"] == "critical" and found[0]["evidence"]["received"]["signature"]
    assert (await LedgerService.head())[0] == 4


async def test_truncated_history_is_reported(host):
    from fluid.utils.sync import FullSync
    snapshot = list(host.items)
    host.items = host.items[:2]
    try:
        result = await FullSync.run("full")
    finally:
        host.items = snapshot
    assert result["error"] == "HOST_HISTORY_TRUNCATED"
    assert await conflicts("host-history-truncated")


async def test_a_changed_host_key_is_rejected(host):
    from fluid.utils.sync import FullSync
    snapshot, signer = list(host.items), host.signer
    host.rotate_key()
    try:
        result = await FullSync.run("full")
    finally:
        host.items, host.signer = snapshot, signer
    assert result["status"] == "failed" and result["error"] == "HOST_KEY_MISMATCH"
    assert (await conflicts("host-key-changed"))[0]["severity"] == "critical"


async def test_artifact_observation_against_trusted_reference(host, monkeypatch):
    from fluid.utils import observe
    from wf_peering.utils import netcheck
    from wf_peering.settings import settings
    script = STATE["script"]
    v1 = hashlib.sha256(script).hexdigest()
    manifest = { "artifact": "users_e2ee", "algorithm": "sha256", "latest": "v1",
                 "versions": [{ "version": "v1", "sha256": v1 }] }

    async def reference(url, max_bytes=0):
        return json.dumps(manifest).encode()

    monkeypatch.setattr(netcheck, "reference", reference)
    monkeypatch.setitem(settings.references, "users_e2ee", "https://raw.githubusercontent.com/x/y/main/manifest.json")
    record = { "id": "users_e2ee", "algorithm": "sha256", "hash": v1, "url": "/users/static/js/e2ee.js",
               "served_version": "v1" }
    assert (await observe.observe(record))["status"] == "verified"

    manifest["versions"].append({ "version": "v2", "sha256": "2" * 64 })
    manifest["latest"] = "v2"
    outdated = await observe.observe(record)
    assert outdated["status"] == "outdated" and outdated["latest_version"] == "v2"

    host.files["/users/static/js/e2ee.js"] = b"console.log('manipulated')\n"
    try:
        assert (await observe.observe(record))["status"] == "served-mismatch"
    finally:
        host.files["/users/static/js/e2ee.js"] = script

    unknown = dict(record, hash="9" * 64)
    host.files["/users/static/js/e2ee.js"] = b"x"
    try:
        result = await observe.observe(dict(unknown, hash=hashlib.sha256(b"x").hexdigest()))
        assert result["status"] == "reference-mismatch"
    finally:
        host.files["/users/static/js/e2ee.js"] = script

    results = await observe.run()
    assert results and results[0]["artifact"] == "users_e2ee"


async def test_format_two_manifests_select_the_artifact(host, monkeypatch):
    from fluid.utils import observe
    from wf_peering.utils import netcheck
    from wf_peering.settings import settings
    script = STATE["script"]
    v1 = hashlib.sha256(script).hexdigest()
    manifest = { "format": 2, "algorithm": "sha256", "artifacts": {
        "users_e2ee": { "latest": "v1", "versions": [{ "version": "v1", "sha256": v1 }] },
        "users_session": { "latest": "v1", "versions": [{ "version": "v1", "sha256": "5" * 64 }] }
    } }

    async def reference(url, max_bytes=0):
        return json.dumps(manifest).encode()

    monkeypatch.setattr(netcheck, "reference", reference)
    monkeypatch.setitem(settings.references, "users_e2ee", "https://raw.githubusercontent.com/x/y/main/manifest.json")
    monkeypatch.setitem(settings.references, "ocean_integrity", "https://raw.githubusercontent.com/x/y/main/manifest.json")
    record = { "id": "users_e2ee", "algorithm": "sha256", "hash": v1, "url": "/users/static/js/e2ee.js",
               "served_version": "v1" }
    assert (await observe.observe(record))["status"] == "verified"
    unlisted = await observe.observe(dict(record, id="ocean_integrity"))
    assert unlisted["status"] == "unreferenced" and unlisted["reference"]["reason"] == "NOT_IN_REFERENCE"


async def test_unserved_records_are_not_observed(host, monkeypatch):
    from fluid.utils import observe
    from wf_peering.services import IntegrityService

    async def current():
        return [{ "provider": "ocean", "records": [{ "record": { "id": "ocean_release:abc", "algorithm": "sha256",
                                                                 "hash": "a" * 64, "served": False } }] }]

    monkeypatch.setattr(IntegrityService, "current", current)
    assert await observe.run() == []


async def test_node_identity_checks(host):
    from wf_peering.services import PeerService
    good = await PeerService.check_node(HOST)
    assert good["ok"] and good["identity"] == "verified"
    assert good["comparison"]["status"] in ("match", "behind", "ahead")
    down = await PeerService.check_node("http://127.0.0.1:8579")
    assert not down.get("ok") and down["error"] in ("UNREACHABLE", "TIMEOUT")

    from tests_fakehost import serve

    async def forged(request):
        response = await host.node_route(request)
        data = json.loads(response.body)
        data["statement"]["url"] = "http://127.0.0.1:8574"
        return JSONResponse(data)

    server, task = await serve(Starlette(routes=[Route("/api/v1/node", forged)]), 8574)
    try:
        bad = await PeerService.check_node("http://127.0.0.1:8574")
        assert bad["error"] == "INVALID_NODE_SIGNATURE"
    finally:
        server.should_exit = True
        await task


async def test_tls_failures_are_classified(tmp_path, monkeypatch):
    from wf_peering.utils import netcheck
    from wf_peering.protocol.netpolicy import Target
    ca_path, leaf, (self_key, self_name), now = _pki(tmp_path)

    def trusting():
        context = ssl.create_default_context(cafile=str(ca_path))
        return context

    monkeypatch.setattr(netcheck, "tls_context", trusting)

    async def run(cert, key, server_name, port):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        async def handle(reader, writer):
            try: await reader.read(10)
            except Exception: pass
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", port, ssl=context)
        try:
            return await netcheck.tls(Target("https", server_name, port, False), "127.0.0.1")
        finally:
            server.close()

    valid = await run(*leaf("peer.test", now - datetime.timedelta(days=1), now + datetime.timedelta(days=20)), "peer.test", 8581)
    assert valid["ok"] and valid["days_left"] >= 19 and len(valid["key"]) == 64, valid
    mismatch = await run(*leaf("peer.test", now - datetime.timedelta(days=1), now + datetime.timedelta(days=20)), "other.test", 8582)
    assert mismatch == { **mismatch, "ok": False, "error": "HOSTNAME_MISMATCH" }
    expired = await run(*leaf("peer.test", now - datetime.timedelta(days=20), now - datetime.timedelta(days=1)), "peer.test", 8583)
    assert expired["error"] == "CERT_EXPIRED"
    rogue = await run(*leaf("peer.test", now - datetime.timedelta(days=1), now + datetime.timedelta(days=5),
                            issuer_key=self_key, issuer=self_name), "peer.test", 8584)
    assert rogue["error"] in ("UNTRUSTED_ISSUER", "CERT_INVALID", "SELF_SIGNED_CHAIN")


async def test_trust_reflects_proven_misbehaviour_and_missing_independence():
    from wf_peering.services import TrustService
    report = await TrustService.assess()
    host = report["host"]
    signals = { signal["id"]: signal for signal in host["signals"] }
    assert signals["equivocation_free"]["value"] == 0
    assert signals["host_key_stable"]["value"] == 0
    assert host["level"] in ("critical", "unclear")
    assert host["status"] == "unclear" or host["score"] <= 5
    assert report["population"]["independent"] == 0


async def test_stored_copy_verifies(host):
    from wf_peering import jobs
    from wf_peering.services import StateService
    await jobs.verify()
    assert (await StateService.get("ledger_verification"))["valid"]


async def test_peer_is_a_plain_app_with_its_own_api_paths(client):
    from webfluid.core.constants import ADDITIVES
    assert not ADDITIVES
    node = (await client.get("/api/v1/node")).json()["statement"]
    assert node["role"] == "peer" and node["host"] == HOST and node["software"].startswith("peering-app/")
    assert (await client.get("/peering/api/v1/node")).status_code == 404
    sync = (await client.get("/api/v1/sync")).json()
    assert sync["role"] == "peer" and sync["next_full_sync"] and isinstance(sync["runs"], list)
    assert (await client.get("/api/v1/integrity/observations")).status_code == 200
    assert (await client.get("/api/health")).json()["status"] == "ok"
    page = await client.get("/")
    assert page.status_code == 200 and "/wf-peering/static/js/status.js" in page.text and 'data-api="/api/v1"' in page.text
    assert (await client.get("/wf-peering/static/js/status.js")).status_code == 200


async def test_an_interrupted_sync_is_closed_and_a_fresh_one_is_not_due(host):
    from webfluid.core.ext import db
    from fluid.utils.sync import FullSync
    from wf_peering.models.sync import SyncRun
    from wf_peering.protocol.entries import utc_now

    async with db.async_executor(model=SyncRun) as e:
        await e.insert(SyncRun("interrupted-run", "daily", utc_now(), "2026-10-09"))
    assert await FullSync.close_interrupted() == 1
    async with db.async_executor(model=SyncRun) as e:
        row = (await e.exec(select(SyncRun).where(SyncRun.id == "interrupted-run"))).first()
        assert (row.status, row.error) == ("failed", "INTERRUPTED") and row.finished_at

    assert (await FullSync.run("startup"))["status"] == "success"
    assert await FullSync.due() is False


@pytest.fixture(scope="session", autouse=True)
async def host(fluid, fakehost_module):
    from tests_fakehost import FakeHost, serve
    fake = FakeHost(HOST)
    fake.append("peering:genesis", { "node": fake.signer.fingerprint }, "host")
    script = b"console.log('e2ee v1')\n"
    fake.files["/users/static/js/e2ee.js"] = script
    fake.append("peering:integrity", { "artifact": "users_e2ee", "provider": "users", "fingerprint": "f" * 64,
                                       "previous": None, "run": "r1", "context": { "uptime": 5 },
                                       "record": { "id": "users_e2ee", "additive": "users", "algorithm": "sha256",
                                                   "hash": hashlib.sha256(script).hexdigest(), "version": "v1",
                                                   "served_version": "v1", "url": "/users/static/js/e2ee.js" } },
                "artifact:users_e2ee")
    server, task = await serve(fake.app(), PORT)
    STATE["script"] = script
    yield fake
    server.should_exit = True
    await task


@pytest.fixture(scope="session", autouse=True)
def fakehost_module():
    path = pathlib.Path(__file__).with_name("fakehost.py")
    spec = importlib.util.spec_from_file_location("tests_fakehost", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["tests_fakehost"] = module
    spec.loader.exec_module(module)
