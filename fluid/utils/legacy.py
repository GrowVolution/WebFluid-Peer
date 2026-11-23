from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select, func
from wf_peering.models.integrity import Observation
from wf_peering.models.ledger import LedgerEntry
from wf_peering.models.state import Conflict, TrustSnapshot
from wf_peering.models.sync import RemoteCheckpoint, SyncRun
from wf_peering.protocol import entries, network
from wf_peering.services import JournalService, StateService
from pathlib import Path
import json

from ..models import NetAppEntry
from .clock import Clock

MARKER = "legacy_migration"
VERSION = 1


class LegacyMigration:
    @staticmethod
    async def inventory() -> dict:
        counts = {}
        async with db.async_executor(model=LedgerEntry) as e:
            for name, model in (("ledger", LedgerEntry), ("sync_runs", SyncRun), ("observations", Observation),
                                ("remote_checkpoints", RemoteCheckpoint), ("conflicts", Conflict),
                                ("trust", TrustSnapshot)):
                counts[name] = (await e.exec(select(func.count()).select_from(model), scalars=False)).scalar() or 0
        return { "counts": counts, "host_key": await StateService.get("host_key") }

    @classmethod
    async def run(cls) -> dict:
        done = await StateService.get(MARKER)
        if done and done.get("version") == VERSION and done.get("status") in ("imported", "empty"): return done
        found = await cls.inventory()
        key = found["host_key"]
        if not found["counts"]["ledger"]:
            outcome = { "version": VERSION, "status": "empty", "at": Clock.ts(), "inventory": found["counts"] }
            await StateService.set(MARKER, outcome)
            return outcome
        if not key:
            outcome = { "version": VERSION, "status": "unassignable", "at": Clock.ts(), "inventory": found["counts"],
                        "reason": "NO_PINNED_HOST_KEY" }
            await StateService.set(MARKER, outcome)
            return outcome
        app = network.app_id(key)
        try:
            imported = await cls._import(app, key)
        except ValueError as exc:
            outcome = { "version": VERSION, "status": "failed", "at": Clock.ts(), "app": app, "reason": str(exc),
                        "inventory": found["counts"] }
            await StateService.set(MARKER, outcome)
            log_factory.warning(f"[peering] Legacy import for {app} stopped: {exc}. Nothing was imported.")
            return outcome
        outcome = { "version": VERSION, "status": "imported", "at": Clock.ts(), "app": app, "context": "wf-ledger-v1",
                    "imported": imported, "inventory": found["counts"] }
        await StateService.set(MARKER, outcome)
        await JournalService.append("peering:legacy-imported", { "app": app, "entries": imported })
        return outcome

    @staticmethod
    async def _import(app: str, key: str) -> int:
        async with db.async_executor(model=LedgerEntry) as e:
            rows = list((await e.exec(select(LedgerEntry).order_by(LedgerEntry.seq))).all())
            existing = set((await e.exec(select(NetAppEntry.seq).where(NetAppEntry.app == app))).all())
            previous_seq, previous_hash, imported = 0, entries.GENESIS, 0
            for row in rows:
                content = json.loads(row.content)
                if entries.problems(content): raise ValueError(f"INVALID_ENTRY_{row.seq}")
                value = entries.entry_hash(content)
                if value != row.hash or entries.check_link(content, previous_hash, previous_seq):
                    raise ValueError(f"BROKEN_CHAIN_{row.seq}")
                if not entries.verify_hash(key, entries.LEDGER_CONTEXT, value, row.signature):
                    raise ValueError(f"INVALID_SIGNATURE_{row.seq}")
                previous_seq, previous_hash = row.seq, value
                if row.seq in existing: continue
                await e.insert(NetAppEntry(app, row.seq, value, entries.entry_leaf(content), content["kind"],
                                           content["subject"], row.content, row.signature))
                imported += 1
        return imported

    @classmethod
    async def export(cls, target: Path) -> Path:
        data = { "format": "wf-peering-legacy-export-1", "exported_at": Clock.ts(),
                 "inventory": await cls.inventory(), "marker": await StateService.get(MARKER) }
        async with db.async_executor(model=SyncRun) as e:
            data["sync_runs"] = [{ "id": row.id, "kind": row.kind, "day": row.day, "status": row.status,
                                   "to_seq": row.to_seq, "local_root": row.local_root, "error": row.error }
                                 for row in (await e.exec(select(SyncRun))).all()]
            data["observations"] = [{ "artifact": row.artifact, "ts": row.ts, "status": row.status,
                                      "observed": row.observed_hash, "claimed": row.claimed_hash }
                                    for row in (await e.exec(select(Observation))).all()]
            data["remote_checkpoints"] = [{ "node": row.node_id, "day": row.day, "hash": row.hash,
                                            "content": json.loads(row.content), "signature": row.signature,
                                            "context": "wf-checkpoint-v1" }
                                          for row in (await e.exec(select(RemoteCheckpoint))).all()]
            data["conflicts"] = [{ "kind": row.kind, "severity": row.severity, "subject": row.subject,
                                   "summary": row.summary, "detected_at": row.detected_at }
                                 for row in (await e.exec(select(Conflict))).all()]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        return target
