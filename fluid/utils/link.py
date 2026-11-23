from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select
from wf_peering.protocol import network
from wf_peering.services import BindingService, IdentityService, JournalService, StateService
from wf_peering.settings import settings, NET_API
from wf_peering.utils.netclient import NetClient, NetError
import asyncio

from ..exceptions import NetFailure
from ..models import NetObject, NetSource
from .clock import Clock
from .store import ObjectStore

MAX_PAGES = 20
FATAL = ("NETWORK_MISMATCH", "SELF_JOIN", "REVOKED", "ROLE_CHANGE_NOT_ALLOWED", "ANCHORED_WITHOUT_GENESIS")
SUBMITTED = "peer_submitted_cursor"


class UpstreamLink:
    status: dict = { "state": "idle" }
    _task: asyncio.Task | None = None

    @classmethod
    def snapshot(cls) -> dict:
        return dict(cls.status)

    @classmethod
    def ensure(cls):
        if cls._task is None or cls._task.done(): cls._task = asyncio.create_task(cls._loop())

    @classmethod
    def stop(cls):
        if cls._task and not cls._task.done(): cls._task.cancel()

    @classmethod
    async def _loop(cls):
        delay = 2
        while True:
            try:
                await cls.cycle()
                delay = settings.net_interval
            except asyncio.CancelledError: raise
            except (NetError, NetFailure) as exc:
                cls.status = dict(cls.status, state="rejected" if exc.code in FATAL else "retrying", error=exc.code,
                                  since=Clock.ts())
                delay = 600 if exc.code in FATAL else min(max(delay, 2) * 2, 300)
            except Exception as exc:
                log_factory.exception(exc, "[peering] The upstream link failed.")
                cls.status = dict(cls.status, state="retrying", error=type(exc).__name__, since=Clock.ts())
                delay = min(max(delay, 2) * 2, 300)
            await asyncio.sleep(delay)

    @classmethod
    async def join(cls) -> dict:
        from .network import NetworkService
        topology = NetworkService.topology
        cls.status = dict(cls.status, state="joining", upstream=topology.upstream, error=None)
        joined = await NetClient.join(topology.upstream, topology.role, topology.public if topology.role == "master"
                                      else None)
        entry = joined["binding"]["entry"]["node"]
        source = f"master:{entry}"
        await ObjectStore.put(joined["binding"]["genesis"], source)
        for item in joined["binding"].get("members") or []: await ObjectStore.put(item, source)
        if joined["admission"]: await ObjectStore.put(joined["admission"], source)
        for item in (await NetClient.get(topology.upstream, f"{NET_API}/policy", 256 * 1024)).get("policies") or []:
            await ObjectStore.put(item, source)
        await cls.source(entry, joined["binding"]["entry"]["url"])
        cls.status = dict(cls.status, state="joined", net=joined["net"], entry=joined["binding"]["entry"],
                          duplicate=joined["duplicate"], anchor=joined["binding"]["anchor"], since=Clock.ts())
        await JournalService.append("peering:joined", { "net": joined["net"], "entry": joined["binding"]["entry"],
                                                       "duplicate": joined["duplicate"] })
        if topology.role == "master":
            from .operator import OperatorService
            await OperatorService.maintain()
        return joined

    @staticmethod
    async def source(node: str, url: str):
        async with db.async_executor(model=NetSource) as e:
            row = (await e.exec(select(NetSource).where(NetSource.node == node))).first()
            if row is None: await e.insert(NetSource(node, url))
            elif row.url != url: row.url = url

    @classmethod
    async def sources(cls) -> list[tuple[str, str]]:
        binding = await BindingService.get()
        if binding is None: return []
        own = IdentityService.node_id()
        if settings.is_peer:
            entry = binding.get("entry") or {}
            return [(entry["node"], entry["url"])] if entry.get("node") else []
        members = await ObjectStore.membership()
        out = []
        for member in members.masters():
            if member.node == own or not member.url or member.revoked_at: continue
            await cls.source(member.node, member.url)
            out.append((member.node, member.url))
        return out

    @classmethod
    async def pull(cls, node: str, url: str) -> dict:
        net = await BindingService.network()
        async with db.async_executor(model=NetSource) as e:
            cursor = (await e.exec(select(NetSource.cursor).where(NetSource.node == node))).first() or 0
        totals = { "stored": 0, "duplicate": 0, "rejected": 0, "pages": 0 }
        for _ in range(MAX_PAGES):
            page = await NetClient.get(url, f"{NET_API}/objects?after={cursor}&limit=200")
            if not isinstance(page, dict) or page.get("net") != net: raise NetFailure("NETWORK_MISMATCH")
            items = page.get("objects")
            if not isinstance(items, list): raise NetFailure("INVALID_PAGE")
            if not items: break
            cursors = [item.get("cursor") for item in items if isinstance(item, dict)]
            if len(cursors) != len(items) or any(type(value) is not int for value in cursors) \
                    or cursors != sorted(cursors) or cursors[0] <= cursor:
                raise NetFailure("NO_PROGRESS")
            try:
                async with db.async_executor(model=NetObject):
                    for item in items:
                        _, status = await ObjectStore.put(item.get("object"), f"master:{node}")
                        key = status if status in ("stored", "duplicate") else "rejected"
                        totals[key] += 1
                    async with db.ensured_async_executor(model=NetSource) as e:
                        row = (await e.exec(select(NetSource).where(NetSource.node == node))).first()
                        row.cursor = cursors[-1]
                        row.last_ok = Clock.ts()
                        row.last_error = None
                        row.failures = 0
            except Exception:
                ObjectStore.forget()
                raise
            cursor = cursors[-1]
            totals["pages"] += 1
            if not page.get("more"): break
        return totals

    @classmethod
    async def sync(cls) -> dict:
        report = {}
        for node, url in await cls.sources():
            try: report[node] = await cls.pull(node, url)
            except (NetError, NetFailure) as exc:
                report[node] = { "error": exc.code }
                async with db.async_executor(model=NetSource) as e:
                    row = (await e.exec(select(NetSource).where(NetSource.node == node))).first()
                    if row:
                        row.last_error = exc.code[:128]
                        row.failures += 1
        from .apps import AppRegistry
        await AppRegistry.ensure_rows()
        cls.status = dict(cls.status, last_sync=Clock.ts(), sync=report)
        return report

    @classmethod
    async def submit(cls) -> dict:
        binding = await BindingService.get()
        entry = (binding or {}).get("entry") or {}
        if not entry.get("node"): return { "submitted": 0 }
        cursor = await StateService.get(SUBMITTED, 0)
        async with db.async_executor(model=NetObject) as e:
            rows = list((await e.exec(select(NetObject).where(
                NetObject.cursor > cursor, NetObject.signer == IdentityService.node_id(), NetObject.type == "attest"
            ).order_by(NetObject.cursor).limit(100))).all())
        if not rows: return { "submitted": 0 }
        status, data = await NetClient.send(entry["url"], entry["node"], f"{NET_API}/attest",
                                            { "attestations": [ObjectStore.load(row) for row in rows] })
        if status != 200: raise NetFailure(str((data or {}).get("detail") if isinstance(data, dict) else status))
        await StateService.set(SUBMITTED, rows[-1].cursor)
        return { "submitted": len(rows), "answer": data }

    @classmethod
    async def cycle(cls):
        from .network import NetworkService
        binding = await BindingService.get()
        topology = NetworkService.topology
        if topology.upstream and (binding is None or not binding.get("admission")): await cls.join()
        elif topology.upstream and cls.status.get("state") not in ("joined", "synced"): await cls.join()
        if await BindingService.network() is None: return
        report = await cls.sync()
        failed = [item["error"] for item in report.values() if "error" in item]
        if report and len(failed) == len(report): raise NetFailure(failed[0])
        if settings.is_peer: await cls.submit()
        cls.status["state"] = "synced"
