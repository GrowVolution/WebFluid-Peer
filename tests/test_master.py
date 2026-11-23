from datetime import timedelta
import hashlib, json, os, pytest

STATE = {}


def signer(label: str):
    from wf_peering.protocol.signing import Signer
    return Signer(hashlib.sha256(f"master-tests\n{label}".encode()).digest())


async def net():
    from wf_peering.services import BindingService
    return await BindingService.network()


async def master_id():
    from wf_peering.services import IdentityService
    return IdentityService.node_id()


async def join(client, member, role: str, url: str | None = None, net_value="__bound__", aud=None, nonce=None,
               ts=None):
    from wf_peering.protocol import network
    challenge = (await client.get("/api/v1/net/challenge")).json()
    body = {
        "net": (await net()) if net_value == "__bound__" else net_value, "role": role, "url": url,
        "aud": aud or challenge["aud"], "nonce": nonce or challenge["nonce"],
        "app": network.app_id(member.public_key) if role == "app" else None, "ts": ts or network.now_ts()
    }
    request = network.sign(member, network.JOIN_CONTEXT, body)
    return await client.post("/api/v1/net/join", content=json.dumps({ "join": request })), challenge


async def signed(client, member, path: str, payload: dict, nonce: str | None = None, ts: str | None = None,
                 aud: str | None = None):
    from wf_peering.protocol import network
    from wf_peering.protocol.canonical import canonical
    raw = canonical(payload)
    header = network.request_header(member, await net(), aud or await master_id(), "POST", path, raw,
                                    nonce or os.urandom(12).hex(), ts)
    return await client.post(path, content=raw, headers={ "X-WF-Net-Auth": header })


def head(member, net_value: str, app: str, size: int, ts: str | None = None, salt: str = "") -> dict:
    from wf_peering.protocol import network
    from wf_peering.protocol.merkle import leaf_hash, root
    leaves = [leaf_hash(f"{app}-{index}{salt}".encode()) for index in range(1, size + 1)]
    return network.sign(member, network.APP_HEAD_CONTEXT, {
        "net": net_value, "app": app, "seq": size, "hash": hashlib.sha256(f"{app}{size}{salt}".encode()).hexdigest(),
        "root": root(leaves), "ts": ts or network.now_ts()
    })


def app_statement(member, url: str, role: str = "app") -> dict:
    from wf_peering.protocol import network
    return network.sign(member, network.NODE_CONTEXT, { "net": None, "role": role, "url": url, "software": "tests",
                                                        "boot": "boot", "debug": True, "ts": network.now_ts() })


async def admit_app(client, monkeypatch, member, url):
    from fluid.utils import network as module

    async def node(target, api):
        return app_statement(member, url)["body"], app_statement(member, url)

    monkeypatch.setattr(module.NetClient, "node", staticmethod(node))
    response, _ = await join(client, member, "app", url)
    assert response.status_code == 200, response.text
    return response.json()


async def test_primary_founds_the_network_once(fluid, root):
    from wf_peering.services import BindingService, IdentityService
    from fluid.utils.network import NetworkService
    binding = await BindingService.get()
    assert binding["anchor"] == "founded" and binding["net"].startswith("n1.")
    assert binding["genesis"]["body"]["primary"]["key"] == IdentityService.public_key()
    assert (root / "keys" / "genesis.json").is_file()
    again = await NetworkService.ensure("other-name", { "inactive_days": 1, "attest_max_age": 60, "min_groups": 1 })
    assert again["net"] == binding["net"]
    STATE["net"] = binding["net"]


async def test_master_router_inventory(fluid):
    paths = set()

    def walk(routes, prefix=""):
        for route in routes:
            context = getattr(route, "include_context", None)
            if context is not None:
                walk(context.included_router.routes, prefix + context.prefix)
            else: paths.add(prefix + getattr(route, "path", ""))

    walk(fluid.routes)
    for path in ("/api/v1/net/join", "/api/v1/net/challenge", "/api/v1/net/objects", "/api/v1/apps",
                 "/api/v1/apps/{app}/evidence", "/api/v1/net/receipts/{event}", "/"):
        assert path in paths, path
    assert not paths & { "/docs", "/redoc", "/openapi.json" }


async def test_peer_join_rules(client):
    peer = signer("peer")
    response, _ = await join(client, peer, "peer")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["admission"]["body"]["member"]["role"] == "peer" and data["duplicate"] is False
    assert data["admission"]["body"]["member"]["url"] is None
    again, _ = await join(client, peer, "peer")
    assert again.json()["duplicate"] is True
    assert again.json()["admission"] == data["admission"]
    other, _ = await join(client, signer("x"), "peer", net_value="n1.AAAAAAAAAAAAAAAAAAAAAA")
    assert other.json()["detail"] == "NETWORK_MISMATCH"
    wrong, _ = await join(client, signer("y"), "peer", aud="A" * 22)
    assert wrong.json()["detail"] == "WRONG_AUDIENCE"
    first, challenge = await join(client, signer("z"), "peer")
    replay, _ = await join(client, signer("w"), "peer", nonce=challenge["nonce"])
    assert first.status_code == 200 and replay.json()["detail"] == "UNKNOWN_CHALLENGE"
    stale, _ = await join(client, signer("v"), "peer", ts="2020-01-01T00:00:00Z")
    assert stale.json()["detail"] == "STALE_REQUEST"
    role, _ = await join(client, peer, "master", "http://127.0.0.1:9")
    assert role.json()["detail"] in ("ROLE_CHANGE_NOT_ALLOWED", "URL_UNREACHABLE")
    STATE["peer"] = peer


async def test_app_join_checks_the_origin(client, monkeypatch):
    from fluid.utils import network as module
    from wf_peering.utils.netclient import NetError
    app = signer("app-one")
    data = await admit_app(client, monkeypatch, app, "https://one.example")
    assert data["admission"]["body"]["member"]["app"].startswith("app1.")
    impostor = signer("impostor")

    async def foreign(target, api):
        statement = app_statement(app, "https://two.example")
        return statement["body"], statement

    monkeypatch.setattr(module.NetClient, "node", staticmethod(foreign))
    refused, _ = await join(client, impostor, "app", "https://two.example")
    assert refused.json()["detail"] == "URL_NOT_VERIFIED"

    async def down(target, api): raise NetError("UNREACHABLE")

    monkeypatch.setattr(module.NetClient, "node", staticmethod(down))
    unreachable, _ = await join(client, impostor, "app", "https://two.example")
    assert unreachable.json()["detail"] == "URL_UNREACHABLE"
    STATE["app"] = app
    STATE["app_id"] = data["admission"]["body"]["member"]["app"]


async def test_heartbeat_sightings_replay_and_roles(client):
    from wf_peering.protocol import network
    from fluid.utils.store import ObjectStore
    app, identifier = STATE["app"], STATE["app_id"]
    payload = { "head": head(app, await net(), identifier, 3), "name": "App One" }
    nonce = os.urandom(12).hex()
    first = await signed(client, app, "/api/v1/net/heartbeat", payload, nonce)
    assert first.status_code == 200, first.text
    seen = first.json()["seen"]
    assert network.check(seen, (network.SEEN_CONTEXT,), await net())[1] is None
    replay = await signed(client, app, "/api/v1/net/heartbeat", payload, nonce)
    assert replay.json()["detail"] == "REPLAYED"
    wrong = await signed(client, app, "/api/v1/net/heartbeat", payload, aud="B" * 22)
    assert wrong.json()["detail"] == "WRONG_AUDIENCE"
    stale = await signed(client, app, "/api/v1/net/heartbeat", payload, ts="2020-01-01T00:00:00Z")
    assert stale.json()["detail"] == "STALE_REQUEST"
    peer = await signed(client, STATE["peer"], "/api/v1/net/heartbeat", payload)
    assert peer.json()["detail"] == "ROLE_NOT_ALLOWED"
    stranger = await signed(client, signer("stranger"), "/api/v1/net/heartbeat", payload)
    assert stranger.json()["detail"] == "NOT_A_MEMBER"
    forged_policy = network.sign(app, network.POLICY_CONTEXT, { "net": await net(), "seq": 1, "prev": network.ZERO,
                                                               "inactive_days": 1, "attest_max_age": 60,
                                                               "min_groups": 1, "ts": network.now_ts() })
    assert (await ObjectStore.put(forged_policy, "test"))[1] == "ROLE_NOT_ALLOWED"
    future = head(app, await net(), identifier, 4, network.now_ts(network.parse_ts(network.now_ts()) + timedelta(hours=1)))
    assert (await signed(client, app, "/api/v1/net/heartbeat", { "head": future })).json()["detail"] == "HEAD_FROM_FUTURE"


async def test_inactivity_is_strictly_greater_than_the_policy(client):
    from fluid.utils.apps import AppRegistry
    from fluid.utils.clock import Clock
    from wf_peering.protocol import network
    identifier = STATE["app_id"]
    seen = network.parse_ts(await AppRegistry.last_seen(identifier))
    try:
        Clock.offset = seen + timedelta(days=30) - Clock.now().replace() + (Clock.offset or timedelta())
        assert await AppRegistry.active(identifier)
        found = (await client.get("/api/v1/apps")).json()["items"]
        assert identifier in [item["app"] for item in found]
        Clock.offset += timedelta(seconds=1)
        assert not await AppRegistry.active(identifier)
        found = (await client.get("/api/v1/apps")).json()["items"]
        assert identifier not in [item["app"] for item in found]
        hidden = (await client.get("/api/v1/apps", params={ "inactive": "1" })).json()["items"]
        assert identifier in [item["app"] for item in hidden]
        before = Clock.ts()
        rejoin = await signed(client, STATE["app"], "/api/v1/net/heartbeat",
                              { "head": head(STATE["app"], await net(), identifier, 3) }, ts=before)
        assert rejoin.status_code == 200, rejoin.text
        assert await AppRegistry.active(identifier)
        assert before <= await AppRegistry.last_seen(identifier) <= Clock.ts()
    finally:
        Clock.offset = None
    assert await AppRegistry.active(identifier)


async def test_operator_declaration_is_signed_bound_and_served_with_the_imprint(client):
    from fluid.utils.operator import OperatorService
    from fluid.utils.legal import imprint_digest
    from wf_peering.protocol import network
    from wf_peering.services import IdentityService
    await OperatorService.maintain()
    document = (await client.get("/api/v1/net/operator")).json()
    declaration = document["declaration"]
    body, problem = network.check(declaration, (network.OPERATOR_CONTEXT,), await net())
    assert problem is None and body["by"] == IdentityService.node_id() and body["url"] == "http://127.0.0.1:8571"
    assert body["imprint"] == imprint_digest(document["imprint"]) == document["imprint_digest"] and document["current"]
    assert body["operator"] == { "name": "Beispiel Peering e.V.", "form": "association", "country": "DE",
                                 "ids": [{ "scheme": "register", "country": "DE", "authority": "Amtsgericht Musterstadt",
                                           "type": "VR", "number": "VR 12345" }] }
    assert document["imprint"]["address"] == ["Musterweg 1", "12345 Musterstadt", "Deutschland"]
    assert "Musterweg" not in str(declaration) and "kontakt@example.org" not in str(declaration)
    assert "hosting" not in document["imprint"] and "backups_days" not in str(document)
    listed = (await client.get("/api/v1/net/operators")).json()["operators"]
    assert declaration in listed
    assert await OperatorService.maintain() == declaration


async def test_operator_declaration_changes_with_the_imprint_and_refreshes(client):
    from fluid.utils.clock import Clock
    from fluid.utils.operator import OperatorService, REFRESH
    from wf_peering.protocol import network
    first = await OperatorService.own()
    config = OperatorService.config
    original = config["LEGAL"]["operator"]["name"]
    try:
        config["LEGAL"]["operator"]["name"] = "Beispiel Peering eV (umbenannt)"
        changed = await OperatorService.maintain()
        assert changed["body"]["seq"] == first["body"]["seq"] + 1
        assert changed["body"]["prev"] == network.object_id(first)
        assert changed["body"]["operator"]["name"] == "Beispiel Peering eV (umbenannt)"
        page = (await client.get("/imprint")).text
        assert "Beispiel Peering eV (umbenannt)" in page
        assert (await client.get("/api/v1/net/operator")).json()["declaration"] == changed
    finally:
        config["LEGAL"]["operator"]["name"] = original
    restored = await OperatorService.maintain()
    assert restored["body"]["seq"] == first["body"]["seq"] + 2
    try:
        Clock.offset = timedelta(seconds=REFRESH + 5)
        refreshed = await OperatorService.maintain()
        assert refreshed["body"]["seq"] == restored["body"]["seq"] + 1 and refreshed["body"]["operator"] == restored["body"]["operator"]
    finally:
        Clock.offset = None
    stale = [item for item in await OperatorService.latest() if item["body"]["by"] == first["body"]["by"]]
    assert len(stale) == 1 and stale[0] == refreshed


async def test_foreign_or_misbound_declarations_are_refused_by_the_store(client):
    from fluid.utils.store import ObjectStore
    from wf_peering.protocol import network
    operator = { "name": "Fremd", "form": "company", "country": "DE", "ids": [] }
    stranger = network.sign(signer("stranger"), network.OPERATOR_CONTEXT, {
        "net": await net(), "seq": 1, "prev": network.ZERO, "url": "https://stranger.example", "operator": operator,
        "imprint": "a" * 64, "ts": network.now_ts() })
    assert (await ObjectStore.put(stranger, "test"))[1] == "ROLE_NOT_ALLOWED"
    from wf_peering.services import IdentityService
    misbound = network.sign(IdentityService.signer, network.OPERATOR_CONTEXT, {
        "net": await net(), "seq": 99, "prev": "b" * 64, "url": "https://elsewhere.example", "operator": operator,
        "imprint": "a" * 64, "ts": network.now_ts() })
    assert (await ObjectStore.put(misbound, "test"))[1] == "URL_MISMATCH"


async def test_primary_policy_changes_are_signed_objects(fluid):
    from fluid.utils.network import NetworkService
    from fluid.utils.store import ObjectStore
    obj = await NetworkService.maintain_policy({ "inactive_days": 10, "attest_max_age": 26 * 3600, "min_groups": 2 })
    assert obj["body"]["seq"] == 1
    current, conflicts, _ = await ObjectStore.policy()
    assert current["inactive_days"] == 10 and not conflicts
    await NetworkService.maintain_policy({ "inactive_days": 30, "attest_max_age": 26 * 3600, "min_groups": 2 })
    assert (await ObjectStore.policy())[0]["seq"] == 2


async def test_events_blocks_and_receipts(client):
    from wf_peering.protocol import chain, network
    from fluid.utils.chain import ChainService
    app, identifier = STATE["app"], STATE["app_id"]

    def event(kind, key=None, nonce=None, net_value=None):
        body = { "net": net_value or STATE["net"], "app": identifier, "ns": "test", "type": kind, "commit": "c" * 64,
                 "nonce": nonce or os.urandom(12).hex(), "ts": network.now_ts() }
        if key: body["key"] = key
        return network.sign(app, network.EVENT_CONTEXT, body)

    mint, spend, double = event("test:mint"), event("test:consume", "token:9"), event("test:consume", "token:9")
    first = (await signed(client, app, "/api/v1/net/events", { "event": mint })).json()
    assert first["status"] == "submitted" and first["confirmation"]["finality"] == "none"
    assert (await signed(client, app, "/api/v1/net/events", { "event": spend })).json()["status"] == "submitted"
    rejected = (await signed(client, app, "/api/v1/net/events", { "event": double })).json()
    assert rejected["status"] == "rejected" and rejected["reason"] == "ALREADY_CONSUMED"
    block = await ChainService.close_block()
    assert block["body"]["height"] == 1 and len(block["body"]["events"]) == 2
    receipt = (await client.get(f"/api/v1/net/receipts/{network.object_id(spend)}")).json()
    assert receipt["status"] == "included" and receipt["position"]["height"] == 1
    again = (await signed(client, app, "/api/v1/net/events", { "event": spend })).json()
    assert again["event_id"] == receipt["event_id"] and again["status"] == "included"
    later = event("test:consume", "token:9")
    assert (await signed(client, app, "/api/v1/net/events", { "event": later })).json()["reason"] == "ALREADY_CONSUMED"
    foreign = event("test:mint", net_value="n1.AAAAAAAAAAAAAAAAAAAAAA")
    assert (await signed(client, app, "/api/v1/net/events", { "event": foreign })).json()["detail"] \
        == "EVENT_NETWORK_MISMATCH"
    genesis = (await client.get("/api/v1/net/genesis")).json()["genesis"]
    members = (await client.get("/api/v1/net/objects", params={ "limit": 200 })).json()["objects"]
    admissions = [item["object"] for item in members if item["object"]["t"] == network.MEMBER_CONTEXT]
    verified = chain.verify_receipt(receipt, genesis, admissions, anchor=STATE["net"])
    assert verified["status"] == "included" and verified["finality"] == "none"
    STATE["receipt"] = receipt


async def test_evidence_and_verdict_from_raw_objects(client):
    from wf_peering.protocol import evidence, network
    from wf_peering.services import IdentityService
    from fluid.utils.apps import AppRegistry
    from fluid.utils.store import ObjectStore
    app, identifier = STATE["app"], STATE["app_id"]
    current = head(app, STATE["net"], identifier, 5)
    await signed(client, app, "/api/v1/net/heartbeat", { "head": current })
    await AppRegistry.attest(identifier, current["body"], "first")
    bundle = (await client.get(f"/api/v1/apps/{identifier}/evidence")).json()
    operators = { "primary-org": [IdentityService.node_id()], "peer-org": [STATE["peer"].fingerprint] }
    result = evidence.evaluate(bundle, STATE["net"], operators)
    assert result["status"] == "single-witness" and result["independence"]["independent_groups"] == 1
    attestation = network.sign(STATE["peer"], network.ATTEST_CONTEXT, {
        "net": STATE["net"], "app": identifier, "kind": "head",
        "head": { key: current["body"][key] for key in ("seq", "hash", "root") }, "via": "origin",
        "observed_at": network.now_ts(), "checks": { "chain": "verified", "consistency": "first" }
    })
    answer = (await signed(client, STATE["peer"], "/api/v1/net/attest", { "attestations": [attestation] })).json()
    assert answer["results"][0]["status"] == "stored"
    relayed = dict(attestation, key=IdentityService.public_key())
    answer = (await signed(client, STATE["peer"], "/api/v1/net/attest", { "attestations": [relayed] })).json()
    assert answer["results"][0]["status"] == "SIGNER_NOT_SENDER"
    bundle = (await client.get(f"/api/v1/apps/{identifier}/evidence")).json()
    result = evidence.evaluate(bundle, STATE["net"], operators)
    assert result["status"] == "witnessed" and result["independence"]["proving"] == 2
    assert evidence.evaluate(bundle, STATE["net"], None)["status"] == "single-witness"
    assert evidence.evaluate(bundle, "n1.AAAAAAAAAAAAAAAAAAAAAA", operators)["status"] == "invalid"
    fork = head(app, STATE["net"], identifier, 5, salt="fork")
    assert (await ObjectStore.put(fork, "test"))[1] == "stored"
    bundle = (await client.get(f"/api/v1/apps/{identifier}/evidence")).json()
    assert evidence.evaluate(bundle, STATE["net"], operators)["status"] == "conflict"
    assert len(bundle["conflicts"]) == 1 and len(bundle["conflicts"][0]["objects"]) == 2


async def test_search_detail_and_paging(client, monkeypatch):
    other = signer("app-two")
    await admit_app(client, monkeypatch, other, "https://two-shop.example")
    found = (await client.get("/api/v1/apps", params={ "q": "two-shop" })).json()
    assert [item["origin"] for item in found["items"]] == ["https://two-shop.example"]
    paged = (await client.get("/api/v1/apps", params={ "size": 1, "page": 2 })).json()
    assert paged["pages"] == 2 and len(paged["items"]) == 1 and paged["total"] == 2
    detail = (await client.get(f"/api/v1/apps/{STATE['app_id']}")).json()
    assert detail["verdict"]["status"] in ("conflict", "single-witness") and detail["responder"]
    assert (await client.get("/api/v1/apps/app1.nope")).json()["detail"] == "INVALID_APP"
    first = (await client.get("/api/v1/net/objects", params={ "limit": 2 })).json()
    assert first["more"] and len(first["objects"]) == 2
    second = (await client.get("/api/v1/net/objects", params={ "after": first["next"], "limit": 2 })).json()
    assert second["objects"][0]["cursor"] > first["next"] - 1


async def test_host_selected_reference_does_not_establish_independent_trust(fluid, monkeypatch):
    from fluid.utils import observe
    from wf_peering.settings import settings
    from wf_peering.utils import netcheck
    data = b"untrusted code"
    value = hashlib.sha256(data).hexdigest()
    record = { "id": "widget", "algorithm": "sha256", "hash": value, "url": "/widget.js",
               "reference": { "manifest": "https://raw.githubusercontent.com/example/ref/main/manifest.json" } }
    manifest = { "artifact": "widget", "algorithm": "sha256", "latest": "v1",
                 "versions": [{ "version": "v1", "sha256": value }] }

    async def get(*args, **kwargs): return { "status": 200, "body": data }
    async def reference(*args): return json.dumps(manifest).encode()

    monkeypatch.setattr(netcheck, "get", get)
    monkeypatch.setattr(netcheck, "reference", reference)
    monkeypatch.setattr(settings, "references", {})
    result = await observe.observe("https://app.example", record)
    assert result["status"] == "unreferenced" and result["reference"]["origin"] == "host-supplied"
    monkeypatch.setitem(settings.references, "widget", record["reference"]["manifest"])
    monkeypatch.setattr(settings, "debug", True)
    assert (await observe.observe("https://app.example", record))["status"] == "verified"
    monkeypatch.setattr(settings, "debug", False)
    moving = await observe.observe("https://app.example", record)
    assert moving["status"] == "unreferenced" and moving["reference"]["reason"] == "REFERENCE_NOT_PINNED"
    monkeypatch.setitem(settings.references, "widget",
                        "https://raw.githubusercontent.com/example/ref/" + "ab12" * 10 + "/manifest.json")
    assert (await observe.observe("https://app.example", record))["status"] == "verified"
    crlf = { "artifact": "widget", "algorithm": "sha256", "latest": "v1",
             "versions": [{ "version": "v1", "sha256": value, "http": { "sha256": "e" * 64 } }] }

    async def strict(*args): return json.dumps(crlf).encode()

    monkeypatch.setattr(netcheck, "reference", strict)
    assert (await observe.observe("https://app.example", record))["status"] == "reference-mismatch"


@pytest.mark.parametrize("versions,latest", [
    ([{ "version": "v1", "sha256": "g" * 64 }], "v1"),
    ([{ "version": "v1", "sha256": "a" * 64 }] * 2, "v1"),
    ([{ "version": "v1", "sha256": "a" * 64 }], "absent"),
    ([{ "version": "v1", "sha256": "a" * 64 }], [])
])
def test_malformed_references_are_rejected(versions, latest):
    from fluid.utils.observe import parse_manifest
    assert parse_manifest(json.dumps({ "artifact": "widget", "versions": versions, "latest": latest }).encode()) is None


@pytest.mark.parametrize("data", [b'{"algorithm": ["sha256"]}', b'[' * 2000 + b']' * 2000])
def test_invalid_reference_types_and_depth_are_rejected(data):
    from fluid.utils.observe import parse_manifest
    assert parse_manifest(data) is None
