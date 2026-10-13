from webfluid.utils.logging import factory as log_factory
from datetime import datetime, timedelta, UTC
import asyncio

from wf_peering import NodeRole, __version__
from wf_peering.protocol.entries import parse_ts, to_ts
from wf_peering.protocol.trust import Signal
from wf_peering.services.journal import Journal
from wf_peering.services.peers import Peers, check_node
from wf_peering.services.store import State
from wf_peering.settings import settings, HOST_API
from wf_peering.utils import netcheck

HOUR = 3600
DAY = 86400


class PeerRole(NodeRole):
    name = "peer"

    def __init__(self, version: str | None = None):
        self.software = f"peering-app/{version or '0'} wf-peering/{__version__}"

    async def startup(self) -> None:
        from .sync import HostLink
        await Journal.append("peering:peer-start", { "host": settings.host })
        HostLink.ensure()

    async def heartbeat(self) -> None:
        from .sync import HostLink
        HostLink.ensure()

    async def discover(self) -> None:
        report = await check_node(settings.host)
        await State.set("host_check", report)
        try:
            status, data, _ = await netcheck.get_json(settings.host, f"{HOST_API}/peers", 512 * 1024)
            if status == 200 and isinstance(data, dict):
                for peer in (data.get("peers") or [])[:settings.max_peers]:
                    if isinstance(peer, dict) and isinstance(peer.get("url"), str):
                        await Peers.remember(peer["url"], "host-reported", None, None)
        except netcheck.CheckError as exc:
            log_factory.warning(f"[peering] Reading the host's peer directory failed: {exc.code}")

    async def checkpoint_basis(self, day: str, moment: datetime) -> tuple[int, str, dict]:
        from .sync import FullSync
        deadline = moment + timedelta(seconds=settings.checkpoint_grace)
        run = await FullSync.for_day(day)
        while run is not None and run.status == "running" and datetime.now(UTC) < deadline:
            await asyncio.sleep(5)
            run = await FullSync.for_day(day)

        if run is not None and run.status == "success":
            late = run.finished_at and parse_ts(run.finished_at) > moment
            return run.to_seq or 0, "verified", { "status": "verified", "id": run.id, "finished_at": run.finished_at,
                                                  "to_seq": run.to_seq, "late": bool(late) }

        last = await FullSync.last_success()
        status = "overlap" if run is not None and run.status == "running" else "stale"
        return (last.to_seq or 0) if last else 0, status, {
            "status": status,
            "id": last.id if last else None,
            "finished_at": last.finished_at if last else None,
            "to_seq": last.to_seq if last else None,
            "day_run": run.id if run else None,
            "day_run_status": run.status if run else "missing"
        }

    async def publish_checkpoint(self, signed: dict) -> None:
        from .sync import HostLink
        await HostLink.send({ "type": "checkpoint", **signed })

    async def signals(self, now: datetime) -> list:
        from .sync import HostLink, FullSync
        signals = []
        link = HostLink.snapshot()
        beat = link.get("last_heartbeat")
        age = (now - parse_ts(beat)).total_seconds() if beat else None
        fresh = 100 if link.get("state") == "connected" and age is not None and age < settings.heartbeat_interval * 4 else 0
        signals.append(Signal("heartbeat_fresh", "reachability", fresh if beat else None, 5, "normal", "local", beat,
                              None, detail={ "state": link.get("state"), "error": link.get("error") }))

        last = await FullSync.last_success()
        sync_age = (now - parse_ts(last.finished_at)).total_seconds() if last and last.finished_at else None
        signals.append(Signal("full_sync_fresh", "integrity",
                              None if sync_age is None else (100 if sync_age < 26 * HOUR else (50 if sync_age < 50 * HOUR else 10)),
                              15, "high", "local", last.finished_at if last else None, None,
                              detail={ "age_seconds": int(sync_age) if sync_age is not None else None }))
        runs = await FullSync.runs(14)
        recent = [run for run in runs if run["started_at"] >= to_ts(now - timedelta(days=7))]
        if recent:
            failed = sum(1 for run in recent if run["status"] == "failed")
            signals.append(Signal("sync_failures_7d", "history", max(0, 100 - 25 * failed), 5, "normal", "local",
                                  recent[0]["started_at"], 2 * DAY, detail={ "failed": failed, "runs": len(recent) }))
        return signals

    async def observation(self, artifact: str) -> dict | None:
        from .observe import latest
        return await latest(artifact)

    async def status(self) -> dict:
        from .sync import HostLink, FullSync
        last = await FullSync.last_success()
        return {
            "link": HostLink.snapshot(),
            "last_sync": {
                "id": last.id, "finished_at": last.finished_at, "to_seq": last.to_seq, "root": last.local_root
            } if last else None,
            "host_key": await State.get("host_key") or settings.host_key
        }
