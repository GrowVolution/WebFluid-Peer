from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select, delete
from wf_peering.exceptions import CanonicalError
from wf_peering.protocol import network
from wf_peering.protocol.canonical import canonical_text, strict_loads
from wf_peering.protocol.signing import b64encode
from wf_peering.services import BindingService, IdentityService, JournalService
from wf_peering.settings import settings, NET_API, APP_NET_API
from wf_peering.utils.netclient import NetClient, NetError
from datetime import timedelta
from pathlib import Path
import json, secrets

from ..exceptions import NetFailure
from ..models import NetApp, NetNonce
from .clock import Clock
from .store import ObjectStore

CHALLENGE_TTL = 120
MAX_BODY = 256 * 1024
WRITES = {
    f"{NET_API}/heartbeat": ("app",),
    f"{NET_API}/events": ("app",),
    f"{NET_API}/rotate": ("app",),
    f"{NET_API}/attest": ("master", "peer")
}


class NetworkService:
    topology = None
    operator_info: dict | None = None
    _challenges: dict[str, float] = {}

    @classmethod
    def configure(cls, topology, operator=None):
        cls.topology = topology
        if not isinstance(operator, dict):
            cls.operator_info = None
            return
        cls.operator_info = { key: str(operator[key])[:128] for key in ("name", "contact") if operator.get(key) }

    @staticmethod
    def genesis_file() -> Path:
        return settings.key_file.parent / "genesis.json"

    @classmethod
    async def ensure(cls, name: str, policy: dict) -> dict | None:
        binding = await BindingService.get()
        if binding: return binding
        backup = cls.genesis_file()
        if backup.is_file():
            genesis = strict_loads(backup.read_bytes())
            body, net, problem = network.genesis_of(genesis)
            if problem or body["primary"]["key"] != IdentityService.public_key():
                raise NetFailure("GENESIS_BACKUP_FOREIGN", 500, { "file": str(backup) })
            await BindingService.found(genesis)
            await ObjectStore.put(genesis, "self")
            await JournalService.append("peering:genesis-restored", { "net": net })
            return await BindingService.get()
        if settings.anchor:
            raise NetFailure("ANCHORED_WITHOUT_GENESIS", 500, { "anchor": settings.anchor })
        if not cls.topology.primary: return None
        genesis = network.sign(IdentityService.signer, network.GENESIS_CONTEXT, {
            "name": name, "primary": { "node": IdentityService.node_id(), "key": IdentityService.public_key(),
                                       "url": settings.origin },
            "policy": policy, "created_at": Clock.ts()
        })
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes((canonical_text(genesis) + "\n").encode("utf-8"))
        binding = await BindingService.found(genesis)
        await ObjectStore.put(genesis, "self")
        log_factory.warning(f"[peering] Founded network {binding['net']}. Set PEERING_NETWORK_ANCHOR to pin it.")
        return binding

    @classmethod
    async def is_primary(cls) -> bool:
        genesis = await BindingService.genesis()
        return genesis is not None and genesis["body"]["primary"]["key"] == IdentityService.public_key()

    @classmethod
    async def maintain_policy(cls, wanted: dict) -> dict | None:
        if not await cls.is_primary(): return None
        current, conflicts, _ = await ObjectStore.policy()
        if conflicts or all(current[key] == wanted[key] for key in network.DEFAULT_POLICY): return None
        net = await BindingService.network()
        obj = network.sign(IdentityService.signer, network.POLICY_CONTEXT, dict(wanted, net=net, seq=current["seq"] + 1,
                                                                           prev=current["id"] or network.ZERO,
                                                                           ts=Clock.ts()))
        await ObjectStore.put(obj, "self")
        await JournalService.append("peering:policy", { "seq": obj["body"]["seq"], "policy": wanted })
        return obj

    @classmethod
    def challenge(cls, net: str | None) -> dict:
        now = Clock.now().timestamp()
        for nonce, expires in list(cls._challenges.items()):
            if expires < now: cls._challenges.pop(nonce, None)
        if len(cls._challenges) > 10000: raise NetFailure("TOO_MANY_CHALLENGES", 503)
        nonce = b64encode(secrets.token_bytes(24))
        cls._challenges[nonce] = now + CHALLENGE_TTL
        return { "nonce": nonce, "aud": IdentityService.node_id(), "net": net, "ts": Clock.ts() }

    @classmethod
    def redeem(cls, nonce: str) -> bool:
        expires = cls._challenges.pop(nonce, None)
        return expires is not None and expires >= Clock.now().timestamp()

    @staticmethod
    async def used(signer: str, nonce: str) -> bool:
        async with db.async_executor(model=NetNonce) as e:
            result = await e.exec(select(NetNonce).where(NetNonce.signer == signer, NetNonce.nonce == nonce))
            if result.first() is not None: return True
            await e.insert(NetNonce(signer, nonce, Clock.ts()))
            return False

    @staticmethod
    async def prune_nonces():
        since = (Clock.now() - timedelta(seconds=network.NONCE_WINDOW)).strftime("%Y-%m-%dT%H:%M:%SZ")
        async with db.async_executor(model=NetNonce) as e:
            await e.exec(delete(NetNonce).where(NetNonce.ts < since), scalars=False)

    @classmethod
    async def authenticate(cls, header: str | None, method: str, path: str, raw: bytes) -> tuple[dict, str, str]:
        if not header: raise NetFailure("UNAUTHENTICATED", 401)
        if len(raw) > MAX_BODY: raise NetFailure("TOO_LARGE", 413)
        net = await BindingService.network()
        if net is None: raise NetFailure("NOT_READY", 503)
        try: obj = network.read_header(header)
        except CanonicalError as exc: raise NetFailure(str(exc), 400) from exc
        seen = []

        def remember(signer: str, nonce: str) -> bool:
            seen.append((signer, nonce))
            return False

        body, problem = network.check_request(obj, IdentityService.node_id(), method, path, raw, Clock.now(), net,
                                              remember)
        if problem: raise NetFailure(problem, 401 if problem != "NETWORK_MISMATCH" else 409)
        if await cls.used(*seen[0]): raise NetFailure("REPLAYED", 401)
        role = await cls.role_of(body["by"], obj["key"])
        if role is None: raise NetFailure("NOT_A_MEMBER", 403)
        if role not in WRITES.get(path, ()): raise NetFailure("ROLE_NOT_ALLOWED", 403)
        return body, role, obj["key"]

    @staticmethod
    async def role_of(node: str, key: str) -> str | None:
        members = await ObjectStore.membership()
        member = members.get(node) if members else None
        if member is not None and member.key == key and member.revoked_at is None: return member.role
        async with db.async_executor(model=NetApp) as e:
            result = await e.exec(select(NetApp).where(NetApp.key == key))
            row = result.first()
        if row is not None and await ObjectStore.current_key(row.app) == key: return "app"
        return None

    @staticmethod
    def parse(raw: bytes) -> dict:
        try: data = strict_loads(raw, MAX_BODY)
        except CanonicalError as exc: raise NetFailure(str(exc), 413 if str(exc) == "TOO_LARGE" else 400) from exc
        if not isinstance(data, dict): raise NetFailure("INVALID_BODY")
        return data

    @classmethod
    async def admit(cls, request: dict) -> dict:
        binding = await BindingService.get()
        if binding is None: raise NetFailure("NOT_READY", 503)
        net = binding["net"]
        body, problem = network.check(request, (network.JOIN_CONTEXT,))
        if problem: raise NetFailure(problem)
        if body["net"] not in (None, net): raise NetFailure("NETWORK_MISMATCH", 409)
        if body["aud"] != IdentityService.node_id(): raise NetFailure("WRONG_AUDIENCE", 401)
        if body["by"] == IdentityService.node_id(): raise NetFailure("SELF_JOIN", 409)
        if abs((Clock.now() - network.parse_ts(body["ts"])).total_seconds()) > network.CLOCK_SKEW:
            raise NetFailure("STALE_REQUEST", 401)
        if not cls.redeem(body["nonce"]): raise NetFailure("UNKNOWN_CHALLENGE", 401)
        members = await ObjectStore.membership()
        existing = members.get(body["by"])
        if existing is not None and existing.revoked_at is not None: raise NetFailure("REVOKED", 403)
        if body["role"] == "app" and body["app"] != network.app_id(request["key"]): raise NetFailure("INVALID_APP")
        verified_url = body["url"]
        if body["role"] in ("master", "app"):
            api = NET_API if body["role"] == "master" else APP_NET_API
            try: statement, _ = await NetClient.node(body["url"], api)
            except NetError as exc: raise NetFailure("URL_UNREACHABLE", 422, { "reason": exc.code }) from exc
            if statement["by"] != body["by"] or statement["role"] != body["role"] or statement["url"] != body["url"]:
                raise NetFailure("URL_NOT_VERIFIED", 422)
        if existing is not None:
            admission = await ObjectStore.get(existing.admission) if existing.admission else None
            duplicate = True
            if existing.role != body["role"]: raise NetFailure("ROLE_CHANGE_NOT_ALLOWED", 409)
        else:
            await ObjectStore.put(request, "self")
            admission = network.sign(IdentityService.signer, network.MEMBER_CONTEXT, {
                "net": net, "member": { "node": body["by"], "key": request["key"], "role": body["role"],
                                        "url": verified_url, "app": body["app"] },
                "join": network.object_id(request), "admitted_at": Clock.ts()
            })
            oid, status = await ObjectStore.put(admission, "self")
            if status != "stored": raise NetFailure(f"ADMISSION_{status}", 500)
            duplicate = False
            await JournalService.append("peering:member-admitted", { "node": body["by"], "role": body["role"] })
        if body["role"] == "app":
            from .apps import AppRegistry
            await AppRegistry.admitted(admission, verified_url)
        policies = await ObjectStore.objects(network.POLICY_CONTEXT)
        chain, seen = [], { network.object_id(admission) } if admission else set()
        for item in await ObjectStore.chain_of(IdentityService.node_id()) + await ObjectStore.chain_of(body["by"]):
            identifier = network.object_id(item)
            if identifier in seen: continue
            seen.add(identifier)
            chain.append(item)
        return {
            "genesis": binding["genesis"], "policies": policies, "admission": admission,
            "members": chain,
            "responder": IdentityService.net_statement(net, cls.operator()), "duplicate": duplicate
        }

    @classmethod
    def operator(cls) -> dict | None:
        return cls.operator_info or None

    @staticmethod
    def dump(value) -> str:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
