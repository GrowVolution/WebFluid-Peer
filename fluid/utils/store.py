from webfluid.core.ext import db
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from wf_peering.exceptions import CanonicalError
from wf_peering.protocol import network
from wf_peering.protocol.canonical import canonical_text
from wf_peering.services import BindingService
import json

from ..models import NetObject
from .clock import Clock

SHORT = {
    network.GENESIS_CONTEXT: "genesis", network.JOIN_CONTEXT: "join", network.MEMBER_CONTEXT: "member",
    network.POLICY_CONTEXT: "policy", network.APP_HEAD_CONTEXT: "app-head", network.SEEN_CONTEXT: "seen",
    network.ATTEST_CONTEXT: "attest", network.ROTATE_CONTEXT: "rotate", network.REVOKE_CONTEXT: "revoke",
    network.EVENT_CONTEXT: "event", network.BLOCK_CONTEXT: "block", network.WITNESS_CONTEXT: "witness",
    network.OPERATOR_CONTEXT: "operator"
}
STORED = tuple(SHORT)
PAGE = 200


def _index(context: str, body: dict) -> tuple[str | None, int | None, str]:
    if context == network.GENESIS_CONTEXT: return None, None, body["created_at"]
    if context == network.JOIN_CONTEXT: return body["by"], None, body["ts"]
    if context == network.MEMBER_CONTEXT: return body["member"]["node"], None, body["admitted_at"]
    if context == network.POLICY_CONTEXT: return None, body["seq"], body["ts"]
    if context == network.APP_HEAD_CONTEXT: return body["app"], body["seq"], body["ts"]
    if context == network.SEEN_CONTEXT: return body["app"], None, body["ts"]
    if context == network.ATTEST_CONTEXT: return body["app"], body["head"]["seq"], body["observed_at"]
    if context == network.ROTATE_CONTEXT: return body["app"], body["seq"], body["ts"]
    if context == network.REVOKE_CONTEXT: return body["subject"], None, body["ts"]
    if context == network.EVENT_CONTEXT: return body["app"], None, body["ts"]
    if context in (network.BLOCK_CONTEXT, network.WITNESS_CONTEXT): return str(body["height"]), body["height"], body["ts"]
    if context == network.OPERATOR_CONTEXT: return body["by"], body["seq"], body["ts"]
    return None, None, network.now_ts()


class ObjectStore:
    _membership = None

    @classmethod
    def forget(cls):
        cls._membership = None

    @staticmethod
    def load(row: NetObject) -> dict:
        return json.loads(row.content)

    @classmethod
    async def objects(cls, context: str, subject: str | None = None, seq: int | None = None) -> list[dict]:
        async with db.ensured_async_executor(model=NetObject) as e:
            stmt = select(NetObject).where(NetObject.type == SHORT[context])
            if subject is not None: stmt = stmt.where(NetObject.subject == subject)
            if seq is not None: stmt = stmt.where(NetObject.seq == seq)
            result = await e.exec(stmt.order_by(NetObject.cursor))
            return [cls.load(row) for row in result.all()]

    @classmethod
    async def get(cls, oid: str) -> dict | None:
        async with db.ensured_async_executor(model=NetObject) as e:
            result = await e.exec(select(NetObject).where(NetObject.oid == oid))
            row = result.first()
            return cls.load(row) if row else None

    @classmethod
    async def page(cls, after: int, limit: int = PAGE) -> list[dict]:
        async with db.ensured_async_executor(model=NetObject) as e:
            result = await e.exec(select(NetObject).where(NetObject.cursor > after)
                                  .order_by(NetObject.cursor).limit(max(1, min(limit, PAGE + 1))))
            return [{ "cursor": row.cursor, "object": cls.load(row) } for row in result.all()]

    @classmethod
    async def last_cursor(cls) -> int:
        async with db.ensured_async_executor(model=NetObject) as e:
            result = await e.exec(select(func.max(NetObject.cursor)), scalars=False)
            return result.scalar() or 0

    @classmethod
    async def count(cls, context: str) -> int:
        async with db.ensured_async_executor(model=NetObject) as e:
            result = await e.exec(select(func.count(NetObject.cursor)).where(NetObject.type == SHORT[context]),
                                  scalars=False)
            return result.scalar() or 0

    @classmethod
    async def membership(cls) -> network.Membership | None:
        genesis = await BindingService.genesis()
        if genesis is None: return None
        if cls._membership is None:
            cls._membership = network.membership(genesis["body"], await cls.objects(network.MEMBER_CONTEXT),
                                                 await cls.objects(network.REVOKE_CONTEXT))
        return cls._membership

    @classmethod
    async def policy(cls) -> tuple[dict, list, list]:
        genesis = await BindingService.genesis()
        return network.policy(genesis["body"], await cls.objects(network.POLICY_CONTEXT))

    @classmethod
    async def admission(cls, node: str) -> dict | None:
        members = await cls.membership()
        member = members.get(node) if members else None
        if member is None or member.admission is None: return None
        return await cls.get(member.admission)

    @classmethod
    async def app_keys(cls, app: str) -> network.AppKeys | None:
        members = await cls.membership()
        member = members.app(app) if members else None
        if member is None: return None
        admission = await cls.get(member.admission)
        return network.app_keys(admission["body"], await cls.objects(network.ROTATE_CONTEXT, app))

    @classmethod
    async def current_key(cls, app: str) -> str | None:
        keys = await cls.app_keys(app)
        return keys.key if keys else None

    @classmethod
    async def chain_of(cls, node: str) -> list[dict]:
        members = await cls.membership()
        out, seen = [], set()
        member = members.get(node) if members else None
        while member is not None and member.admission and member.node not in seen:
            seen.add(member.node)
            item = await cls.get(member.admission)
            if item is None: break
            out.append(item)
            member = members.get(member.admitted_by)
        return list(reversed(out))

    @classmethod
    async def authorize(cls, context: str, body: dict, obj: dict) -> str | None:
        genesis = await BindingService.genesis()
        primary = genesis["body"]["primary"]
        members = await cls.membership()
        signer = members.get(body["by"])
        if context == network.GENESIS_CONTEXT:
            return None if network.object_id(obj) == network.object_id(genesis) else "NETWORK_MISMATCH"
        if context == network.JOIN_CONTEXT: return None
        if context in (network.POLICY_CONTEXT, network.REVOKE_CONTEXT, network.BLOCK_CONTEXT):
            return None if obj["key"] == primary["key"] else "ROLE_NOT_ALLOWED"
        if context == network.MEMBER_CONTEXT:
            if signer is None or signer.role != "master" or signer.key != obj["key"]: return "ROLE_NOT_ALLOWED"
            return None if signer.active_at(body["admitted_at"]) else "ADMITTER_REVOKED"
        if context in (network.SEEN_CONTEXT, network.WITNESS_CONTEXT):
            return None if signer is not None and signer.role == "master" and signer.key == obj["key"] \
                else "ROLE_NOT_ALLOWED"
        if context == network.OPERATOR_CONTEXT:
            if signer is None or signer.role != "master" or signer.key != obj["key"]: return "ROLE_NOT_ALLOWED"
            return None if body["url"] == signer.url else "URL_MISMATCH"
        if context == network.ATTEST_CONTEXT:
            return None if signer is not None and signer.role in ("master", "peer") and signer.key == obj["key"] \
                else "ROLE_NOT_ALLOWED"
        if context in (network.APP_HEAD_CONTEXT, network.EVENT_CONTEXT):
            keys = await cls.app_keys(body["app"])
            if keys is None: return "UNKNOWN_APP"
            return None if obj["key"] in keys.keys else "APP_KEY_MISMATCH"
        if context == network.ROTATE_CONTEXT:
            keys = await cls.app_keys(body["app"])
            if keys is None: return "UNKNOWN_APP"
            return None if obj["key"] in keys.keys else "APP_KEY_MISMATCH"
        return "UNKNOWN_TYPE"

    @classmethod
    async def put(cls, obj, source: str) -> tuple[str | None, str]:
        net = await BindingService.network()
        if net is None: return None, "NOT_BOUND"
        try: body, problem = network.check(obj, STORED, net)
        except (CanonicalError, TypeError, ValueError): body, problem = None, "INVALID_OBJECT"
        if problem: return None, problem
        oid = network.object_id(obj)
        try:
            async with db.ensured_async_executor(model=NetObject) as e:
                result = await e.exec(select(NetObject.cursor).where(NetObject.oid == oid))
                if result.first() is not None: return oid, "duplicate"
                problem = await cls.authorize(obj["t"], body, obj)
                if problem: return oid, problem
                subject, seq, ts = _index(obj["t"], body)
                await e.insert(NetObject(oid, SHORT[obj["t"]], body["by"], subject, seq, ts, canonical_text(obj),
                                         source[:32], Clock.ts()), True)
        except IntegrityError:
            return oid, "duplicate"
        if obj["t"] in (network.MEMBER_CONTEXT, network.REVOKE_CONTEXT): cls.forget()
        return oid, "stored"
