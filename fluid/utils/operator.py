from webfluid.core.ext import db
from sqlalchemy import delete
from wf_peering.protocol import network
from wf_peering.services import BindingService, IdentityService, JournalService

from ..models import NetObject
from . import legal
from .clock import Clock
from .store import ObjectStore

REFRESH = 7 * 86400
SUPERSEDED_RETENTION = network.OPERATOR_MAX_AGE
ABANDONED_RETENTION = 2 * network.OPERATOR_MAX_AGE


class OperatorService:
    config = None
    topology = None

    @classmethod
    def configure(cls, config, topology):
        cls.config, cls.topology = config, topology

    @classmethod
    def wanted(cls) -> tuple[dict | None, dict, str]:
        imprint = legal.public_imprint(cls.config)
        return legal.declared_operator(imprint), imprint, legal.imprint_digest(imprint)

    @staticmethod
    def _rank(item: dict) -> tuple:
        return item["body"]["seq"], item["body"]["ts"], network.object_id(item)

    @classmethod
    async def latest(cls, nodes: list[str] | None = None) -> list[dict]:
        by_node = {}
        for item in await ObjectStore.objects(network.OPERATOR_CONTEXT):
            node = item["body"]["by"]
            if nodes is not None and node not in nodes: continue
            by_node.setdefault(node, []).append(item)
        out = []
        for node in sorted(by_node):
            top = max(item["body"]["seq"] for item in by_node[node])
            out.extend(sorted((item for item in by_node[node] if item["body"]["seq"] == top), key=cls._rank))
        return out

    @classmethod
    async def own(cls) -> dict | None:
        mine = await cls.latest([IdentityService.node_id()])
        return max(mine, key=cls._rank) if mine else None

    @classmethod
    async def maintain(cls, force: bool = False) -> dict | None:
        if cls.topology is None or cls.topology.role != "master": return None
        net = await BindingService.network()
        members = await ObjectStore.membership()
        me = members.get(IdentityService.node_id()) if members else None
        if not net or me is None or me.role != "master" or not me.url: return None
        operator, _, digest = cls.wanted()
        if operator is None: return None
        current = await cls.own()
        body = current["body"] if current else None
        same = body is not None and body["operator"] == operator and body["url"] == me.url and body["imprint"] == digest
        fresh = body is not None and (Clock.now() - network.parse_ts(body["ts"])).total_seconds() < REFRESH
        if same and fresh and not force: return current
        obj = network.sign(IdentityService.signer, network.OPERATOR_CONTEXT, {
            "net": net, "seq": body["seq"] + 1 if body else 1, "prev": network.object_id(current) if current else network.ZERO,
            "url": me.url, "operator": operator, "imprint": digest, "ts": Clock.ts()
        })
        _, status = await ObjectStore.put(obj, "self")
        if status != "stored": return current
        await JournalService.append("peering:operator-declared", { "seq": obj["body"]["seq"], "changed": not same })
        return obj

    @classmethod
    async def document(cls) -> dict:
        _, imprint, digest = cls.wanted()
        declaration = await cls.own()
        return {
            "net": await BindingService.network(), "node": IdentityService.node_id(),
            "declaration": declaration, "imprint": imprint, "imprint_digest": digest,
            "current": declaration is not None and declaration["body"]["imprint"] == digest,
            "fields": { "imprint": list(legal.PUBLIC_FIELDS), "replicated": list(legal.REPLICATED_FIELDS) },
            "generated_at": Clock.ts()
        }

    @classmethod
    async def retention(cls) -> int:
        keep = { network.object_id(item) for item in await cls.latest() }
        now = Clock.now()
        doomed = []
        for item in await ObjectStore.objects(network.OPERATOR_CONTEXT):
            age = (now - network.parse_ts(item["body"]["ts"])).total_seconds()
            identifier = network.object_id(item)
            if (identifier not in keep and age > SUPERSEDED_RETENTION) or age > ABANDONED_RETENTION:
                doomed.append(identifier)
        if not doomed: return 0
        async with db.async_executor(model=NetObject) as e:
            await e.exec(delete(NetObject).where(NetObject.oid.in_(doomed)), scalars=False)
        await JournalService.append("peering:operator-pruned", { "count": len(doomed) })
        return len(doomed)
