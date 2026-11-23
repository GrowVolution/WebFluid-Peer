from webfluid.core.ext import db
from sqlalchemy import select, func
from wf_peering.protocol import chain, network
from wf_peering.services import BindingService, IdentityService, JournalService
from wf_peering.settings import settings
import asyncio

from ..exceptions import NetFailure
from ..models import NetConsumed, NetEvent, NetObject
from .clock import Clock
from .store import ObjectStore

MAX_EVENTS = 256


class ChainService:
    _lock: asyncio.Lock | None = None
    operators: dict = {}

    @classmethod
    def _guard(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @staticmethod
    async def blocks() -> list[dict]:
        return sorted(await ObjectStore.objects(network.BLOCK_CONTEXT), key=lambda item: item["body"]["height"])

    @classmethod
    async def state(cls) -> tuple[chain.ChainState, dict, list]:
        state, events, conflicts = chain.ChainState(), {}, []
        genesis = await BindingService.genesis()
        net = await BindingService.network()
        primary = genesis["body"]["primary"]["key"]
        by_height = {}
        for item in await cls.blocks(): by_height.setdefault(item["body"]["height"], []).append(item)
        for height in sorted(by_height):
            group = by_height[height]
            if len(group) > 1:
                conflicts.append({ "kind": "block-conflict", "height": height,
                                   "objects": sorted(network.object_id(item) for item in group) })
                break
            block = group[0]
            for identifier in block["body"]["events"]:
                if identifier not in events:
                    item = await ObjectStore.get(identifier)
                    if item is not None: events[identifier] = item
            apps = { events[identifier]["body"]["app"] for identifier in block["body"]["events"] if identifier in events }
            keys = {}
            for app in apps:
                found = await ObjectStore.app_keys(app)
                keys[app] = found.keys if found else None
            body, problem = chain.check_block(block, net, primary, state, events, keys.get)
            if problem:
                conflicts.append({ "kind": "block-invalid", "height": height, "reason": problem,
                                   "objects": [network.object_id(block)] })
                break
            chain.apply_block(state, block, body)
            chain.consume(state, events, body)
        return state, events, conflicts

    @classmethod
    async def submit(cls, payload: dict, key: str) -> dict:
        net = await BindingService.network()
        event = payload.get("event")
        body, problem = network.check(event, (network.EVENT_CONTEXT,), net)
        if problem: raise NetFailure(f"EVENT_{problem}")
        if event["key"] != key: raise NetFailure("EVENT_NOT_BY_SENDER", 403)
        if await ObjectStore.current_key(body["app"]) != key: raise NetFailure("APP_KEY_MISMATCH", 403)
        identifier = network.object_id(event)
        async with cls._guard():
            async with db.async_executor(model=NetEvent) as e:
                known = (await e.exec(select(NetEvent).where(NetEvent.event == identifier))).first()
            if known is None:
                oid, status = await ObjectStore.put(event, "self")
                if status not in ("stored", "duplicate"): raise NetFailure(f"EVENT_{status}", 403)
                reason, conflicting = None, None
                if body.get("key") is not None:
                    async with db.async_executor(model=NetConsumed) as e:
                        consumed = (await e.exec(select(NetConsumed).where(NetConsumed.key == body["key"]))).first()
                        pending = (await e.exec(select(NetEvent).where(NetEvent.status == "pending"))).all()
                    if consumed is not None: reason, conflicting = "ALREADY_CONSUMED", consumed.event
                    else:
                        for row in pending:
                            other = await ObjectStore.get(row.event)
                            if other and other["body"].get("key") == body["key"]:
                                reason, conflicting = "ALREADY_CONSUMED", row.event
                                break
                async with db.async_executor(model=NetEvent) as e:
                    await e.insert(NetEvent(identifier, body["app"], "rejected" if reason else "pending", Clock.ts(),
                                            reason, conflicting))
        return await cls.receipt(identifier)

    @classmethod
    async def adopt(cls, state: chain.ChainState) -> int:
        async with db.async_executor(model=NetObject) as e:
            known = select(NetEvent.event)
            rows = list((await e.exec(select(NetObject).where(NetObject.type == "event", NetObject.oid.not_in(known))
                                      .order_by(NetObject.cursor).limit(MAX_EVENTS))).all())
        adopted = 0
        for row in rows:
            if row.oid in state.positions: continue
            item = ObjectStore.load(row)
            key = item["body"].get("key")
            reason, conflicting = None, None
            if key is not None and key in state.consumed: reason, conflicting = "ALREADY_CONSUMED", state.consumed[key]
            async with db.async_executor(model=NetEvent) as e:
                if key is not None and reason is None:
                    for pending in (await e.exec(select(NetEvent).where(NetEvent.status == "pending"))).all():
                        other = await ObjectStore.get(pending.event)
                        if other and other["body"].get("key") == key:
                            reason, conflicting = "ALREADY_CONSUMED", pending.event
                            break
                await e.insert(NetEvent(row.oid, item["body"]["app"], "rejected" if reason else "pending",
                                        row.received_at, reason, conflicting))
            adopted += 1
        return adopted

    @classmethod
    async def close_block(cls) -> dict | None:
        genesis = await BindingService.genesis()
        if genesis is None or genesis["body"]["primary"]["key"] != IdentityService.public_key(): return None
        net = await BindingService.network()
        async with cls._guard():
            state, events, conflicts = await cls.state()
            if not conflicts: await cls.adopt(state)
            if conflicts: return None
            async with db.async_executor(model=NetEvent) as e:
                rows = list((await e.exec(select(NetEvent).where(NetEvent.status == "pending")
                                          .order_by(NetEvent.received_at, NetEvent.event).limit(MAX_EVENTS))).all())
            chosen, keys = [], set()
            for row in rows:
                item = await ObjectStore.get(row.event)
                if item is None: continue
                key = item["body"].get("key")
                if key is not None and (key in state.consumed or key in keys):
                    async with db.async_executor(model=NetEvent) as e:
                        current = (await e.exec(select(NetEvent).where(NetEvent.event == row.event))).first()
                        current.status, current.reason = "rejected", "ALREADY_CONSUMED"
                        current.conflicting = state.consumed.get(key)
                    continue
                if key is not None: keys.add(key)
                chosen.append(row.event)
                events[row.event] = item
            if not chosen: return None
            block = network.sign(IdentityService.signer, network.BLOCK_CONTEXT, {
                "net": net, "height": state.height + 1, "prev": state.head or network.ZERO,
                "root": chain.block_root(chosen), "events": chosen, "ts": Clock.ts()
            })
            oid, status = await ObjectStore.put(block, "self")
            if status != "stored": return None
            await cls.applied(block, events)
        await JournalService.append("peering:block", { "height": block["body"]["height"], "events": len(chosen),
                                                      "block": oid })
        return block

    @classmethod
    async def applied(cls, block: dict, events: dict):
        body = block["body"]
        async with db.async_executor(model=NetEvent) as e:
            for index, identifier in enumerate(body["events"]):
                row = (await e.exec(select(NetEvent).where(NetEvent.event == identifier))).first()
                item = events.get(identifier)
                if row is None and item is not None:
                    row = await e.insert(NetEvent(identifier, item["body"]["app"], "included", Clock.ts()), True)
                if row is not None:
                    row.status, row.height, row.position, row.reason = "included", body["height"], index, None
                key = (item or {}).get("body", {}).get("key")
                if key is not None:
                    if (await e.exec(select(NetConsumed).where(NetConsumed.key == key))).first() is None:
                        await e.insert(NetConsumed(key, identifier, body["height"]))
                    pending = (await e.exec(select(NetEvent).where(NetEvent.status == "pending",
                                                                   NetEvent.event != identifier))).all()
                    for other in pending:
                        candidate = await ObjectStore.get(other.event)
                        if candidate and candidate["body"].get("key") == key:
                            other.status, other.reason, other.conflicting = "rejected", "ALREADY_CONSUMED", identifier

    @classmethod
    async def witness(cls) -> list[dict]:
        genesis = await BindingService.genesis()
        if genesis is None or genesis["body"]["primary"]["key"] == IdentityService.public_key(): return []
        members = await ObjectStore.membership()
        own = members.get(IdentityService.node_id()) if members else None
        if own is None or own.role != "master": return []
        net = await BindingService.network()
        signed = []
        async with cls._guard():
            state, events, conflicts = await cls.state()
            mine = { item["body"]["block"] for item in await ObjectStore.objects(network.WITNESS_CONTEXT)
                     if item["body"]["by"] == IdentityService.node_id() }
            for height in range(1, state.height + 1):
                block_id = state.blocks[height]
                if block_id in mine: continue
                block = await ObjectStore.get(block_id)
                await cls.applied(block, events)
                obj = network.sign(IdentityService.signer, network.WITNESS_CONTEXT, {
                    "net": net, "height": height, "block": block_id, "root": block["body"]["root"], "ts": Clock.ts()
                })
                await ObjectStore.put(obj, "self")
                signed.append(obj)
        return signed

    @classmethod
    async def receipt(cls, identifier: str) -> dict:
        event = await ObjectStore.get(identifier)
        if event is None or event["t"] != network.EVENT_CONTEXT: raise NetFailure("UNKNOWN_EVENT", 404)
        net = await BindingService.network()
        async with db.async_executor(model=NetEvent) as e:
            row = (await e.exec(select(NetEvent).where(NetEvent.event == identifier))).first()
        state, events, conflicts = await cls.state()
        position = state.positions.get(identifier)
        policy = (await ObjectStore.policy())[0]
        receipt = { "event": event, "event_id": identifier, "chain": net, "status": "submitted", "block": None,
                    "position": None, "proof": [], "witnesses": [], "conflicts": conflicts,
                    "confirmation": { "required": policy["min_groups"], "finality": chain.FINALITY } }
        key = event["body"].get("key")
        holder = state.consumed.get(key) if key is not None else None
        if position is None and holder is not None and holder != identifier:
            receipt.update(status="rejected", reason="ALREADY_CONSUMED", conflicting=holder)
            return receipt
        if row is not None and row.status == "rejected" and position is None:
            receipt.update(status="rejected", reason=row.reason, conflicting=row.conflicting)
            return receipt
        if position is None: return receipt
        height, index = position
        block = await ObjectStore.get(state.blocks[height])
        from .operator import OperatorService
        witnesses = [item for item in await ObjectStore.objects(network.WITNESS_CONTEXT, str(height))
                     if item["body"]["block"] == state.blocks[height]]
        receipt.update(status="included", block=block, position={ "height": height, "index": index },
                       proof=chain.proof(block["body"]["events"], index), witnesses=witnesses,
                       operators=await OperatorService.latest(sorted({ item["body"]["by"] for item in witnesses })))
        genesis = await BindingService.genesis()
        members = await ObjectStore.objects(network.MEMBER_CONTEXT)
        rotations = { event["body"]["app"]: await ObjectStore.objects(network.ROTATE_CONTEXT, event["body"]["app"]) }
        verified = chain.verify_receipt(receipt, genesis, members, await ObjectStore.objects(network.REVOKE_CONTEXT),
                                        rotations, cls.operators, policy["min_groups"], net, Clock.now())
        receipt["status"] = verified["status"]
        receipt["confirmation"].update(witness_groups=verified["witness_groups"], unassigned=verified.get("unassigned"),
                                       declared_groups=verified["declared_groups"], declared=verified["declared"],
                                       unresolved=verified["unresolved"], perspective=IdentityService.node_id())
        return receipt

    @staticmethod
    async def stats() -> dict:
        async with db.async_executor(model=NetEvent) as e:
            result = await e.exec(select(NetEvent.status, func.count(NetEvent.event)).group_by(NetEvent.status),
                                  scalars=False)
            counts = { status: count for status, count in result.all() }
        async with db.async_executor(model=NetObject) as e:
            height = (await e.exec(select(func.max(NetObject.seq)).where(NetObject.type == "block"),
                                   scalars=False)).scalar() or 0
        return { "events": counts, "height": height, "block_interval": settings.block_interval }
