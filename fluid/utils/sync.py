from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select
from datetime import datetime, timedelta, UTC
import asyncio, json, secrets, uuid

from wf_peering.models.sync import SyncRun
from wf_peering.protocol import entries
from wf_peering.protocol.handshake import HELLO_CONTEXT, AUTH_CONTEXT, WELCOME_CONTEXT, MAX_MESSAGE
from wf_peering.protocol.signing import verify, fingerprint, valid_ed25519, b64encode
from wf_peering.services.identity import NodeIdentity
from wf_peering.services.journal import Journal
from wf_peering.services.ledger import Ledger, LedgerError
from wf_peering.services.store import State, Conflicts, dumps, loads
from wf_peering.settings import settings, HOST_API, HOST_SOCKET, PROTOCOL_VERSION, SCHEMA_VERSION
from wf_peering.utils import netcheck

FRESH_SYNC = timedelta(hours=26)


class SyncFailure(Exception):
    def __init__(self, code: str, transient: bool = False, detail: dict | None = None):
        super().__init__(code)
        self.code = code
        self.transient = transient
        self.detail = detail or {}


async def pinned_host_key() -> str | None:
    return settings.host_key or await State.get("host_key")


async def accept_host_key(key: str, node: str) -> None:
    pinned = await pinned_host_key()
    if pinned and pinned != key:
        await Conflicts.record(
            "host-key-changed", "critical",
            "The host presented a node key that differs from the pinned one.",
            { "pinned": pinned, "presented": key, "node": node }, subject="host",
            key={ "pinned": pinned, "presented": key }
        )
        raise SyncFailure("HOST_KEY_MISMATCH")
    if not pinned:
        await State.set("host_key", key)
        await Journal.append("peering:host-key-pinned", { "key": key, "node": node, "mode": "trust-on-first-use" })


async def after_ingest(item: dict):
    content = item.get("content") or {}
    kind = content.get("kind")
    if kind in ("peering:integrity", "peering:integrity-missing"):
        from wf_peering.services.integrity import Integrity
        await Integrity.apply_replicated(content)
    elif kind == "peering:checkpoint":
        from wf_peering.services.checkpoints import Checkpoints
        await Checkpoints.remember_remote(content.get("body") or {}, via="host-ledger")


async def ingest(item: dict, host_key: str) -> str:
    outcome = await Ledger.ingest(item, host_key)
    if outcome == "appended": await after_ingest(item)
    return outcome


class HostLink:
    _task: asyncio.Task | None = None
    status: dict = { "state": "idle" }
    _socket = None

    @classmethod
    def ensure(cls):
        if not settings.is_peer: return
        if cls._task is None or cls._task.done():
            cls._task = asyncio.create_task(cls._loop())

    @classmethod
    def stop(cls):
        if cls._task and not cls._task.done(): cls._task.cancel()

    @classmethod
    def snapshot(cls) -> dict:
        return dict(cls.status)

    @classmethod
    async def _loop(cls):
        delay = 2
        while True:
            try:
                await cls._session()
                delay = 2
            except asyncio.CancelledError:
                raise
            except SyncFailure as exc:
                cls.status = dict(cls.status, state="rejected" if exc.code.startswith("HOST_KEY") else "disconnected",
                                  error=exc.code, since=entries.utc_now())
                if exc.code in ("HOST_KEY_MISMATCH", "FORK"): delay = 600
            except Exception as exc:
                code = getattr(exc, "code", None) or type(exc).__name__
                cls.status = dict(cls.status, state="disconnected", error=str(code)[:120], since=entries.utc_now())
            await asyncio.sleep(min(delay, 300))
            delay = min(delay * 2, 300)

    @classmethod
    async def _session(cls):
        from websockets.asyncio.client import connect
        where = netcheck.target(settings.host, (443,) if not settings.allow_insecure else (443, 80))
        addresses = await netcheck.resolve(where)
        address = (addresses["v4"] + addresses["v6"])[0]
        scheme = "wss" if where.scheme == "https" else "ws"
        default = 443 if where.scheme == "https" else 80
        port = "" if where.port == default else f":{where.port}"
        host = f"[{where.host}]" if ":" in where.host else where.host
        kwargs = { "host": address, "port": where.port }
        if where.scheme == "https":
            kwargs.update(ssl=netcheck._context(), server_hostname=where.host)

        cls.status = dict(cls.status, state="connecting", error=None)
        async with connect(
                f"{scheme}://{host}{port}{HOST_SOCKET}", proxy=None, open_timeout=settings.timeout,
                max_size=MAX_MESSAGE, user_agent_header=netcheck.USER_AGENT, **kwargs
        ) as socket:
            host_key = await cls._handshake(socket)
            cls._socket = socket
            connected_at = entries.utc_now()
            cls.status = { "state": "connected", "since": connected_at, "connected_at": connected_at,
                           "last_heartbeat": connected_at, "error": None, "host_key": host_key }
            await Journal.append("peering:host-connected", { "host": settings.host, "key": host_key })
            beat = asyncio.create_task(cls._heartbeats(socket))
            try:
                seq, _ = await Ledger.head()
                await socket.send(json.dumps({ "type": "range", "from": seq + 1, "limit": settings.ledger_page }))
                await cls._receive(socket, host_key)
            finally:
                beat.cancel()
                cls._socket = None
                await Journal.append("peering:host-disconnected", {
                    "host": settings.host, "connected_at": connected_at, "error": cls.status.get("error")
                })

    @classmethod
    async def _handshake(cls, socket) -> str:
        hello = json.loads(await asyncio.wait_for(socket.recv(), timeout=settings.timeout))
        if hello.get("type") == "error": raise SyncFailure(str(hello.get("code") or "REJECTED"))
        statement = hello.get("statement") or {}
        key = statement.get("key")
        if hello.get("type") != "hello" or not valid_ed25519(key) or statement.get("node") != fingerprint(key):
            raise SyncFailure("INVALID_HELLO")
        if not verify(key, HELLO_CONTEXT, statement, hello.get("signature") or ""):
            raise SyncFailure("INVALID_HELLO_SIGNATURE")
        if statement.get("protocol") != PROTOCOL_VERSION or statement.get("schema") != SCHEMA_VERSION:
            raise SyncFailure("PROTOCOL_MISMATCH")
        await accept_host_key(key, statement.get("node"))

        nonce = b64encode(secrets.token_bytes(24))
        auth = {
            "node": NodeIdentity.node_id(), "key": NodeIdentity.public_key(), "url": settings.origin,
            "challenge": statement.get("challenge"), "nonce": nonce, "ts": entries.utc_now(),
            "protocol": PROTOCOL_VERSION, "schema": SCHEMA_VERSION
        }
        await socket.send(json.dumps({ "type": "auth", "statement": auth,
                                       "signature": NodeIdentity.sign(AUTH_CONTEXT, auth) }))
        welcome = json.loads(await asyncio.wait_for(socket.recv(), timeout=settings.timeout))
        if welcome.get("type") == "error": raise SyncFailure(str(welcome.get("code") or "REJECTED"))
        proof = welcome.get("statement") or {}
        if welcome.get("type") != "welcome" or proof.get("nonce") != nonce or proof.get("node") != NodeIdentity.node_id():
            raise SyncFailure("INVALID_WELCOME")
        if not verify(key, WELCOME_CONTEXT, proof, welcome.get("signature") or ""):
            raise SyncFailure("INVALID_WELCOME_SIGNATURE")
        return key

    @classmethod
    async def _heartbeats(cls, socket):
        while True:
            await asyncio.sleep(settings.heartbeat_interval)
            seq, value = await Ledger.head()
            await socket.send(json.dumps({ "type": "heartbeat", "head": { "seq": seq, "hash": value },
                                           "ts": entries.utc_now() }))

    @classmethod
    async def _receive(cls, socket, host_key: str):
        while True:
            raw = await asyncio.wait_for(socket.recv(), timeout=settings.heartbeat_interval * 4)
            try: message = json.loads(raw)
            except ValueError: continue
            kind = message.get("type")
            if kind == "heartbeat":
                cls.status["last_heartbeat"] = entries.utc_now()
                head = message.get("head") or {}
                seq, _ = await Ledger.head()
                if isinstance(head.get("seq"), int) and head["seq"] > seq:
                    await socket.send(json.dumps({ "type": "range", "from": seq + 1, "limit": settings.ledger_page }))
            elif kind in ("entry", "entries"):
                items = [message.get("entry")] if kind == "entry" else message.get("entries") or []
                for item in items:
                    try: await ingest(item, host_key)
                    except LedgerError as exc:
                        if exc.code == "GAP":
                            seq, _ = await Ledger.head()
                            await socket.send(json.dumps({ "type": "range", "from": seq + 1, "limit": settings.ledger_page }))
                            break
                        if exc.code == "FORK":
                            cls.status["error"] = "FORK"
                            raise SyncFailure("FORK")
                        log_factory.warning(f"[peering] Rejected a ledger entry from the host: {exc.code}")
                        await Conflicts.record("invalid-host-entry", "critical",
                                               f"The host sent a ledger entry that failed verification: {exc.code}",
                                               { "code": exc.code, "detail": exc.detail }, subject="host")
                        break
                if kind == "entries" and message.get("more"):
                    seq, _ = await Ledger.head()
                    await socket.send(json.dumps({ "type": "range", "from": seq + 1, "limit": settings.ledger_page }))
            elif kind == "error":
                log_factory.warning(f"[peering] The host reported: {message.get('code')}")

    @classmethod
    async def send(cls, message: dict) -> bool:
        socket = cls._socket
        if socket is None: return False
        try:
            await socket.send(json.dumps(message))
            return True
        except Exception: return False


class FullSync:
    _lock: asyncio.Lock | None = None

    @classmethod
    def _guard(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @staticmethod
    def day_of(moment: datetime) -> str:
        return moment.astimezone(UTC).strftime("%Y-%m-%d")

    @classmethod
    async def run(cls, kind: str = "full", day: str | None = None) -> dict:
        if not settings.is_peer: return { "status": "skipped", "reason": "NOT_A_PEER" }
        if cls._guard().locked(): return { "status": "skipped", "reason": "ALREADY_RUNNING" }
        async with cls._guard():
            run_id = uuid.uuid4().hex
            day = day or cls.day_of(datetime.now(UTC))
            async with db.async_executor(model=SyncRun) as e:
                await e.insert(SyncRun(run_id, kind, entries.utc_now(), day))

            outcome, attempts = None, 0
            while attempts < settings.sync_attempts:
                attempts += 1
                try:
                    outcome = await cls._attempt()
                    outcome["status"] = "success"
                    break
                except SyncFailure as exc:
                    outcome = { "status": "failed", "error": exc.code, "detail": exc.detail }
                    if not exc.transient: break
                except netcheck.CheckError as exc:
                    outcome = { "status": "failed", "error": exc.code, "detail": { "message": exc.detail } }
                except LedgerError as exc:
                    outcome = { "status": "failed", "error": exc.code, "detail": exc.detail }
                    break
                if attempts < settings.sync_attempts: await asyncio.sleep(min(60, 10 * attempts))

            async with db.async_executor(model=SyncRun) as e:
                result = await e.exec(select(SyncRun).where(SyncRun.id == run_id))
                row = result.first()
                row.finished_at = entries.utc_now()
                row.status = outcome["status"]
                row.attempts = attempts
                row.from_seq = outcome.get("from_seq")
                row.to_seq = outcome.get("to_seq")
                row.head_hash = outcome.get("head_hash")
                row.host_root = outcome.get("host_root")
                row.local_root = outcome.get("local_root")
                row.error = outcome.get("error")
                row.detail = dumps(outcome.get("detail") or {})

            await Journal.append("peering:sync", {
                "run": run_id, "kind": kind, "day": day, "status": outcome["status"], "attempts": attempts,
                "to_seq": outcome.get("to_seq"), "root": outcome.get("local_root"), "error": outcome.get("error")
            })
            if outcome["status"] != "success":
                await Conflicts.record("sync-failed", "normal" if outcome.get("error") in ("TIMEOUT", "UNREACHABLE") else "high",
                                       f"The {kind} sync of {day} failed: {outcome.get('error')}",
                                       { "run": run_id, "error": outcome.get("error") }, subject="host", key=run_id)
            return dict(outcome, run=run_id, attempts=attempts)

    @classmethod
    async def _attempt(cls) -> dict:
        host_key = await pinned_host_key()
        status, signed, _ = await netcheck.get_json(settings.host, f"{HOST_API}/ledger/head", 64 * 1024)
        if status != 200 or not isinstance(signed, dict):
            raise SyncFailure("HEAD_UNAVAILABLE", transient=True, detail={ "status": status })
        head, key = signed.get("head") or {}, signed.get("key")
        if not valid_ed25519(key) or not verify(key, entries.HEAD_CONTEXT, head, signed.get("signature") or ""):
            raise SyncFailure("INVALID_HEAD_SIGNATURE")
        if host_key is None:
            await accept_host_key(key, fingerprint(key))
            host_key = key
        elif key != host_key:
            await accept_host_key(key, fingerprint(key))
        if head.get("protocol") != PROTOCOL_VERSION or head.get("schema") != SCHEMA_VERSION:
            raise SyncFailure("SCHEMA_MISMATCH", detail={ "protocol": head.get("protocol"), "schema": head.get("schema") })

        target = head.get("seq")
        if not isinstance(target, int) or target < 0: raise SyncFailure("INVALID_HEAD")
        local, _ = await Ledger.head()
        start = local
        if target < local:
            row = await Ledger.get(target) if target else None
            await Conflicts.record(
                "host-history-truncated", "critical",
                f"The host now reports {target} ledger entries, but this peer already verified {local}.",
                { "reported": head, "signature": signed.get("signature"), "local": local,
                  "local_hash_at_reported": row.hash if row else None },
                subject="host", key={ "reported": target, "local": local, "hash": head.get("hash") }
            )
            raise SyncFailure("HOST_HISTORY_TRUNCATED")

        while local < target:
            status, page, _ = await netcheck.get_json(
                settings.host, f"{HOST_API}/ledger?from={local + 1}&limit={settings.ledger_page}"
            )
            if status != 200 or not isinstance(page, dict):
                raise SyncFailure("RANGE_UNAVAILABLE", transient=True, detail={ "status": status, "from": local + 1 })
            items = page.get("entries") or []
            if not items: raise SyncFailure("INCOMPLETE_RANGE", transient=True, detail={ "from": local + 1 })
            for item in items:
                if (item.get("content") or {}).get("seq", 0) > target: break
                try: await ingest(item, host_key)
                except LedgerError as exc:
                    if exc.code == "GAP": raise SyncFailure("INCOMPLETE_RANGE", transient=True, detail=exc.detail)
                    raise
            local, _ = await Ledger.head()

        _, local_root = await Ledger.root(target)
        stored = await Ledger.get(target) if target else None
        if target and (stored is None or stored.hash != head.get("hash")):
            raise SyncFailure("HEAD_HASH_MISMATCH", detail={ "seq": target })
        if local_root != head.get("root"):
            await Conflicts.record(
                "root-mismatch", "critical",
                f"The host's signed root for {target} entries differs from the root of the verified copy.",
                { "head": head, "signature": signed.get("signature"), "local_root": local_root },
                subject="host", key={ "seq": target, "root": head.get("root") }
            )
            raise SyncFailure("ROOT_MISMATCH")

        report = await Ledger.verify(host_key, target)
        if not report["valid"]:
            raise SyncFailure("LOCAL_COPY_INVALID", detail={ "problems": report["problems"][:20] })

        return { "from_seq": start + 1 if target > start else None, "to_seq": target,
                 "head_hash": head.get("hash"), "host_root": head.get("root"), "local_root": local_root,
                 "detail": { "fetched": target - start } }

    @staticmethod
    async def runs(limit: int = 30) -> list[dict]:
        async with db.async_executor(model=SyncRun) as e:
            result = await e.exec(select(SyncRun).order_by(SyncRun.started_at.desc()).limit(limit))
            return [{
                "id": row.id, "kind": row.kind, "day": row.day, "started_at": row.started_at,
                "finished_at": row.finished_at, "status": row.status, "attempts": row.attempts,
                "from_seq": row.from_seq, "to_seq": row.to_seq, "head_hash": row.head_hash,
                "host_root": row.host_root, "local_root": row.local_root, "error": row.error,
                "detail": loads(row.detail, {})
            } for row in result.all()]

    @staticmethod
    async def for_day(day: str) -> SyncRun | None:
        async with db.async_executor(model=SyncRun) as e:
            result = await e.exec(select(SyncRun).where(SyncRun.day == day, SyncRun.kind == "daily")
                                  .order_by(SyncRun.started_at.desc()).limit(1))
            return result.first()

    @staticmethod
    async def last_success() -> SyncRun | None:
        async with db.async_executor(model=SyncRun) as e:
            result = await e.exec(select(SyncRun).where(SyncRun.status == "success")
                                  .order_by(SyncRun.finished_at.desc()).limit(1))
            return result.first()

    @staticmethod
    async def close_interrupted() -> int:
        async with db.async_executor(model=SyncRun) as e:
            result = await e.exec(select(SyncRun).where(SyncRun.status == "running"))
            rows = list(result.all())
            for row in rows:
                row.status = "failed"
                row.error = "INTERRUPTED"
                row.finished_at = entries.utc_now()
            return len(rows)

    @classmethod
    async def due(cls) -> bool:
        last = await cls.last_success()
        if last is None or not last.finished_at: return True
        return datetime.now(UTC) - entries.parse_ts(last.finished_at) >= FRESH_SYNC
