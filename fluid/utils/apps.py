from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select, func, delete, or_
from wf_peering.exceptions import CanonicalError, IntegrityRecordError
from wf_peering.protocol import entries, evidence, integrity as spec, network
from wf_peering.protocol.canonical import canonical_text
from wf_peering.protocol.merkle import consistency_proof, root
from wf_peering.services import BindingService, IdentityService, JournalService
from wf_peering.settings import settings, APP_NET_API, HOST_API
from wf_peering.utils.netclient import NetClient, NetError
from datetime import timedelta
import asyncio, json

from ..exceptions import NetFailure
from ..models import NetApp, NetAppEntry, NetObject
from .clock import Clock
from .observe import MAX_ARTIFACTS, observe
from .store import ObjectStore

PAGE_SIZE = 25
MAX_PAGE = 50


def _row(row: NetApp) -> dict:
    return {
        "app": row.app, "origin": row.origin, "name": row.name, "joined_via": row.joined_via,
        "admitted_at": row.admitted_at,
        "head": { "seq": row.head_seq, "hash": row.head_hash, "root": row.head_root } if row.head_seq is not None
        else None,
        "replicated_seq": row.replicated_seq, "replicated_at": row.replicated_at,
        "replication_error": row.replication_error
    }


class AppRegistry:
    _running: dict[str, asyncio.Task] = {}
    operators: dict = {}

    @staticmethod
    async def admitted(admission: dict, origin: str | None):
        member = admission["body"]["member"]
        async with db.async_executor(model=NetApp) as e:
            result = await e.exec(select(NetApp).where(NetApp.app == member["app"]))
            row = result.first()
            if row is None:
                await e.insert(NetApp(member["app"], member["key"], admission["body"]["admitted_at"],
                                      origin or member["url"], admission["body"]["by"]))
            elif origin:
                row.origin = origin
                row.metadata_at = Clock.ts()

    @classmethod
    async def ensure_rows(cls) -> int:
        members = await ObjectStore.membership()
        if members is None: return 0
        added = 0
        async with db.async_executor(model=NetApp) as e:
            known = set((await e.exec(select(NetApp.app))).all())
            for member in members.members.values():
                if member.role != "app" or member.app in known: continue
                await e.insert(NetApp(member.app, member.key, member.admitted_at, member.url, member.admitted_by))
                added += 1
        return added

    @staticmethod
    async def get(app: str) -> NetApp | None:
        async with db.async_executor(model=NetApp) as e:
            result = await e.exec(select(NetApp).where(NetApp.app == app))
            return result.first()

    @classmethod
    async def last_seen(cls, app: str) -> str | None:
        members = await ObjectStore.membership()
        member = members.app(app) if members else None
        if member is None: return None
        limit = (Clock.now() + timedelta(seconds=network.CLOCK_SKEW)).strftime("%Y-%m-%dT%H:%M:%SZ")
        async with db.async_executor(model=NetObject) as e:
            result = await e.exec(select(func.max(NetObject.ts)).where(
                NetObject.type == "seen", NetObject.subject == app, NetObject.ts <= limit), scalars=False)
            seen = result.scalar()
        return max(value for value in (seen, member.admitted_at) if value)

    @classmethod
    async def active(cls, app: str, policy: dict | None = None) -> bool:
        policy = policy or (await ObjectStore.policy())[0]
        seen = await cls.last_seen(app)
        if seen is None: return False
        return (Clock.now() - network.parse_ts(seen)).total_seconds() <= policy["inactive_days"] * 86400

    @classmethod
    async def active_apps(cls) -> list[str]:
        policy = (await ObjectStore.policy())[0]
        async with db.async_executor(model=NetApp) as e:
            apps = list((await e.exec(select(NetApp.app).order_by(NetApp.app))).all())
        return [app for app in apps if await cls.active(app, policy)]

    @classmethod
    async def heartbeat(cls, request: dict, key: str, payload: dict, request_id: str) -> dict:
        net = await BindingService.network()
        head = payload.get("head")
        body, problem = network.check(head, (network.APP_HEAD_CONTEXT,), net)
        if problem: raise NetFailure(f"HEAD_{problem}")
        if head["key"] != key: raise NetFailure("HEAD_NOT_BY_SENDER", 403)
        if (network.parse_ts(body["ts"]) - Clock.now()).total_seconds() > network.CLOCK_SKEW:
            raise NetFailure("HEAD_FROM_FUTURE")
        oid, status = await ObjectStore.put(head, "self")
        if status not in ("stored", "duplicate"): raise NetFailure(f"HEAD_{status}", 403)
        app = body["app"]
        seen = network.sign(IdentityService.signer, network.SEEN_CONTEXT, {
            "net": net, "app": app, "request": request_id, "ts": Clock.ts()
        })
        await ObjectStore.put(seen, "self")
        row = await cls.get(app)
        async with db.async_executor(model=NetApp) as e:
            result = await e.exec(select(NetApp).where(NetApp.app == app))
            row = result.first()
            if row is None:
                member = (await ObjectStore.membership()).app(app)
                row = await e.insert(NetApp(app, member.key, member.admitted_at, member.url, member.admitted_by), True)
            if row.head_seq is None or body["seq"] >= row.head_seq:
                row.head_seq, row.head_hash, row.head_root = body["seq"], body["hash"], body["root"]
            name = payload.get("name")
            if isinstance(name, str) and 0 < len(name.strip()) <= 128:
                row.name = name.strip()
                row.metadata_at = Clock.ts()
        if row.replicated_seq < body["seq"]: cls.schedule(app)
        policy = (await ObjectStore.policy())[0]
        return { "seen": seen, "head": oid, "policy": { key: policy[key] for key in network.DEFAULT_POLICY } }

    @classmethod
    def schedule(cls, app: str):
        task = cls._running.get(app)
        if task is not None and not task.done(): return
        cls._running[app] = asyncio.create_task(cls.replicate(app))

    @staticmethod
    async def leaves(app: str, size: int | None = None) -> list[str]:
        async with db.async_executor(model=NetAppEntry) as e:
            stmt = select(NetAppEntry.leaf).where(NetAppEntry.app == app)
            if size is not None: stmt = stmt.where(NetAppEntry.seq <= size)
            return list((await e.exec(stmt.order_by(NetAppEntry.seq))).all())

    @staticmethod
    async def local_head(app: str) -> tuple[int, str]:
        async with db.async_executor(model=NetAppEntry) as e:
            result = await e.exec(select(NetAppEntry).where(NetAppEntry.app == app)
                                  .order_by(NetAppEntry.seq.desc()).limit(1))
            row = result.first()
            return (row.seq, row.hash) if row else (0, entries.GENESIS)

    @classmethod
    async def _store(cls, app: str, keys: list[str], items: list, upto: int) -> int:
        seq, prev = await cls.local_head(app)
        stored = 0
        async with db.async_executor(model=NetAppEntry) as e:
            for item in items:
                if not isinstance(item, dict): raise NetFailure("INVALID_RANGE")
                content, signature = item.get("content"), item.get("signature")
                if entries.problems(content): raise NetFailure("INVALID_ENTRY")
                if content["seq"] > upto: break
                if content["seq"] <= seq: continue
                value = entries.entry_hash(content)
                if content["seq"] != seq + 1 or content["prev"] != prev: raise NetFailure("BROKEN_CHAIN")
                if not any(entries.verify_hash(key, entries.LEDGER_CONTEXT, value, signature or "") for key in keys):
                    raise NetFailure("INVALID_APP_SIGNATURE")
                await e.insert(NetAppEntry(app, content["seq"], value, entries.entry_leaf(content), content["kind"],
                                           content["subject"], canonical_text(content), signature))
                seq, prev = content["seq"], value
                stored += 1
        return stored

    @classmethod
    async def replicate(cls, app: str) -> dict:
        row = await cls.get(app)
        keys = await ObjectStore.app_keys(app)
        if row is None or keys is None or not row.origin: return { "app": app, "status": "skipped" }
        net = await BindingService.network()
        outcome = { "app": app, "status": "failed" }
        try:
            head = await NetClient.get(row.origin, f"{APP_NET_API}/head", 64 * 1024)
            body, problem = network.check(head, (network.APP_HEAD_CONTEXT,), net)
            if problem or body["app"] != app or head["key"] not in keys.keys:
                raise NetFailure(f"HEAD_{problem or 'NOT_BY_APP'}")
            await ObjectStore.put(head, "origin")
            local, _ = await cls.local_head(app)
            previous = local
            if body["seq"] < local:
                raise NetFailure("HISTORY_TRUNCATED")
            while local < body["seq"]:
                page = await NetClient.get(row.origin, f"{HOST_API}/ledger?from={local + 1}&limit={settings.ledger_page}")
                items = page.get("entries") if isinstance(page, dict) else None
                if not isinstance(items, list) or not items: raise NetFailure("INCOMPLETE_RANGE")
                if not await cls._store(app, keys.keys, items, body["seq"]): raise NetFailure("RANGE_NO_PROGRESS")
                local, _ = await cls.local_head(app)
            leaves = await cls.leaves(app, body["seq"])
            seq, value = await cls.local_head(app)
            async with db.async_executor(model=NetAppEntry) as e:
                result = await e.exec(select(NetAppEntry.hash).where(NetAppEntry.app == app,
                                                                     NetAppEntry.seq == body["seq"]))
                at = result.first()
            tree = await asyncio.to_thread(root, leaves)
            if body["seq"] and (at != body["hash"] or tree != body["root"]):
                raise NetFailure("HEAD_MISMATCH")
            attestation = await cls.attest(app, body, "proven" if previous else "first")
            artifacts = await cls.observe(app, row.origin, body)
            async with db.async_executor(model=NetApp) as e:
                result = await e.exec(select(NetApp).where(NetApp.app == app))
                current = result.first()
                current.replicated_seq = body["seq"]
                current.replicated_at = Clock.ts()
                current.replication_error = None
                if current.head_seq is None or body["seq"] >= current.head_seq:
                    current.head_seq, current.head_hash, current.head_root = body["seq"], body["hash"], body["root"]
            outcome = { "app": app, "status": "ok", "seq": body["seq"], "attestation": attestation,
                        "artifacts": artifacts }
        except (NetFailure, NetError) as exc:
            outcome["error"] = exc.code
            async with db.async_executor(model=NetApp) as e:
                result = await e.exec(select(NetApp).where(NetApp.app == app))
                current = result.first()
                if current: current.replication_error = exc.code[:128]
        except Exception as exc:
            log_factory.exception(exc, f"[peering] Replicating {app} failed.")
            outcome["error"] = type(exc).__name__
        return outcome

    @classmethod
    async def attest(cls, app: str, head: dict, consistency: str) -> dict:
        net = await BindingService.network()
        obj = network.sign(IdentityService.signer, network.ATTEST_CONTEXT, {
            "net": net, "app": app, "kind": "head", "head": { key: head[key] for key in ("seq", "hash", "root") },
            "via": "origin", "observed_at": Clock.ts(), "checks": { "chain": "verified", "consistency": consistency }
        })
        await ObjectStore.put(obj, "self")
        return obj

    @classmethod
    async def records(cls, app: str) -> list[dict]:
        current = {}
        async with db.async_executor(model=NetAppEntry) as e:
            result = await e.exec(select(NetAppEntry.content).where(
                NetAppEntry.app == app, or_(NetAppEntry.kind == "peering:integrity",
                                            NetAppEntry.kind == "peering:integrity-missing")).order_by(NetAppEntry.seq))
            for text in result.all():
                content = json.loads(text)
                body = content.get("body") or {}
                if content["kind"] == "peering:integrity-missing":
                    current.pop(body.get("artifact"), None)
                    continue
                try: record = spec.normalize(body.get("record"), body.get("provider"))
                except (IntegrityRecordError, CanonicalError): continue
                current[record["id"]] = record
        return [record for record in current.values() if record.get("served") is not False and record.get("url")]

    @classmethod
    async def observe(cls, app: str, origin: str, head: dict) -> list[dict]:
        net = await BindingService.network()
        out = []
        for record in (await cls.records(app))[:MAX_ARTIFACTS]:
            try: result = await observe(origin, record)
            except Exception as exc:
                log_factory.exception(exc, f"[peering] Observing {record.get('id')} of {app} failed.")
                continue
            obj = network.sign(IdentityService.signer, network.ATTEST_CONTEXT, {
                "net": net, "app": app, "kind": "artifact",
                "head": { key: head[key] for key in ("seq", "hash", "root") }, "via": "origin",
                "observed_at": Clock.ts(), "artifact": {
                    "id": record["id"], "url": record.get("url"), "claimed": record["hash"],
                    "observed": result.get("observed"), "reference": result.get("reference_hash"),
                    "status": result["status"]
                }
            })
            await ObjectStore.put(obj, "self")
            out.append(obj)
        return out

    @classmethod
    async def bundle(cls, app: str) -> dict:
        binding = await BindingService.get()
        if binding is None: raise NetFailure("NOT_READY", 503)
        members = await ObjectStore.membership()
        member = members.app(app)
        admission = await ObjectStore.get(member.admission) if member and member.admission else None
        heads = await ObjectStore.objects(network.APP_HEAD_CONTEXT, app)
        latest = max(heads, key=lambda item: (item["body"]["seq"], item["body"]["ts"])) if heads else None
        attestations = await ObjectStore.objects(network.ATTEST_CONTEXT, app)
        newest = {}
        for item in attestations:
            body = item["body"]
            slot = (body["by"], body["kind"], (body.get("artifact") or {}).get("id"))
            if slot not in newest or body["observed_at"] > newest[slot]["body"]["observed_at"]: newest[slot] = item
        chosen = list(newest.values())
        referenced = { item["body"]["head"]["seq"] for item in chosen if item["body"]["kind"] == "head" }
        by_seq = {}
        for item in heads: by_seq.setdefault(item["body"]["seq"], []).append(item)
        extra = [item for seq in referenced if seq in by_seq for item in by_seq[seq]]
        conflicts = [{ "kind": "app-fork", "objects": group[:2] } for group in by_seq.values()
                     if len({ (item["body"]["hash"], item["body"]["root"]) for item in group }) > 1]
        consistency = []
        if latest is not None:
            leaves = await cls.leaves(app, latest["body"]["seq"])
            if len(leaves) == latest["body"]["seq"]:
                for seq in sorted(referenced):
                    if 0 < seq < latest["body"]["seq"]:
                        consistency.append({ "first": seq, "second": len(leaves), "first_root": root(leaves[:seq]),
                                             "second_root": root(leaves), "proof": consistency_proof(seq, leaves) })
        signers = { item["body"]["by"] for item in chosen } | { member.admitted_by } if member else set()
        chain = []
        seen = set()
        for node in sorted(node for node in signers if node):
            for item in await ObjectStore.chain_of(node):
                identifier = network.object_id(item)
                if identifier not in seen:
                    seen.add(identifier)
                    chain.append(item)
        if admission is not None:
            for item in await ObjectStore.chain_of(member.node):
                identifier = network.object_id(item)
                if identifier not in seen:
                    seen.add(identifier)
                    chain.append(item)
        from .operator import OperatorService
        declarations = await OperatorService.latest(sorted(node for node in signers if node))
        sightings = await ObjectStore.objects(network.SEEN_CONTEXT, app)
        newest_seen = {}
        for item in sightings:
            if item["body"]["by"] not in newest_seen or item["body"]["ts"] > newest_seen[item["body"]["by"]]["body"]["ts"]:
                newest_seen[item["body"]["by"]] = item
        return {
            "responder": IdentityService.net_statement(binding["net"]),
            "genesis": binding["genesis"],
            "policies": await ObjectStore.objects(network.POLICY_CONTEXT),
            "members": chain,
            "revocations": await ObjectStore.objects(network.REVOKE_CONTEXT),
            "app": { "id": app, "admission": admission, "rotations": await ObjectStore.objects(network.ROTATE_CONTEXT,
                                                                                             app) },
            "head": latest, "heads": [item for item in extra if item is not latest], "consistency": consistency,
            "attestations": chosen, "sightings": list(newest_seen.values()), "conflicts": conflicts,
            "operators": declarations,
            "generated_at": Clock.ts()
        }

    @classmethod
    async def verdict(cls, app: str) -> dict:
        bundle = await cls.bundle(app)
        return evidence.evaluate(bundle, bundle["genesis"] and await BindingService.network(), cls.operators,
                                 Clock.now())

    @classmethod
    async def search(cls, query: str | None, page: int, size: int, include_inactive: bool = False) -> dict:
        size = max(1, min(size, MAX_PAGE))
        page = max(1, page)
        policy = (await ObjectStore.policy())[0]
        async with db.async_executor(model=NetApp) as e:
            stmt = select(NetApp).order_by(NetApp.app)
            if query:
                pattern = f"%{query.strip()[:64]}%"
                stmt = stmt.where(or_(NetApp.app.like(pattern), NetApp.origin.like(pattern), NetApp.name.like(pattern)))
            rows = list((await e.exec(stmt)).all())
        items = []
        for row in rows:
            seen = await cls.last_seen(row.app)
            active = seen is not None and (Clock.now() - network.parse_ts(seen)).total_seconds() \
                <= policy["inactive_days"] * 86400
            if not active and not include_inactive: continue
            items.append(dict(_row(row), last_seen=seen, active=active))
        total = len(items)
        start = (page - 1) * size
        return { "items": items[start:start + size], "page": page, "size": size, "total": total,
                 "pages": max(1, -(-total // size)), "generated_at": Clock.ts() }

    @classmethod
    async def detail(cls, app: str) -> dict | None:
        row = await cls.get(app)
        if row is None: return None
        verdict = await cls.verdict(app)
        seen = await cls.last_seen(app)
        async with db.async_executor(model=NetAppEntry) as e:
            length = (await e.exec(select(func.count(NetAppEntry.id)).where(NetAppEntry.app == app),
                                   scalars=False)).scalar() or 0
        leaves = await cls.leaves(app)
        return dict(_row(row), last_seen=seen, active=verdict["status"] != "inactive", chain_length=length,
                    root=root(leaves) if leaves else None, verdict=verdict)

    @classmethod
    async def entries(cls, app: str, start: int, limit: int, subject: str | None = None) -> list[dict]:
        async with db.async_executor(model=NetAppEntry) as e:
            stmt = select(NetAppEntry).where(NetAppEntry.app == app, NetAppEntry.seq >= start)
            if subject is not None: stmt = stmt.where(NetAppEntry.subject == subject)
            result = await e.exec(stmt.order_by(NetAppEntry.seq).limit(max(1, min(limit, 500))))
            return [{ "seq": row.seq, "hash": row.hash, "content": json.loads(row.content), "signature": row.signature }
                    for row in result.all()]

    @classmethod
    async def retention(cls, days: int) -> list[str]:
        policy = (await ObjectStore.policy())[0]
        purged = []
        limit = (policy["inactive_days"] + days) * 86400
        async with db.async_executor(model=NetApp) as e:
            rows = list((await e.exec(select(NetApp))).all())
        for row in rows:
            seen = await cls.last_seen(row.app)
            if seen is None or (Clock.now() - network.parse_ts(seen)).total_seconds() <= limit: continue
            async with db.async_executor(model=NetApp) as e:
                await e.exec(delete(NetAppEntry).where(NetAppEntry.app == row.app), scalars=False)
                result = await e.exec(select(NetApp).where(NetApp.app == row.app))
                current = result.first()
                if current:
                    current.name = None
                    current.origin = None
                    current.metadata_at = None
                    current.replicated_seq = 0
            purged.append(row.app)
        if purged: await JournalService.append("peering:apps-purged", { "apps": purged, "after_days": days })
        return purged
