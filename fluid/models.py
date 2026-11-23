from webfluid.core.constants import EXECUTION
from webfluid.core.ext import db
from sqlalchemy import String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from typing import Optional

PREFIX = "peering_net_"


class NetObject(db.Model):
    __tablename__ = f"{PREFIX}objects"

    cursor: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    oid: Mapped[str] = mapped_column(String(64), unique=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    signer: Mapped[str] = mapped_column(String(22), index=True)
    subject: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    seq: Mapped[Optional[int]]
    ts: Mapped[str] = mapped_column(String(20), index=True)
    content: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32))
    received_at: Mapped[str] = mapped_column(String(20))

    def __init__(self, oid: str, type: str, signer: str, subject: Optional[str], seq: Optional[int], ts: str,
                 content: str, source: str, received_at: str):
        self.oid = oid
        self.type = type
        self.signer = signer
        self.subject = subject
        self.seq = seq
        self.ts = ts
        self.content = content
        self.source = source
        self.received_at = received_at


class NetApp(db.Model):
    __tablename__ = f"{PREFIX}apps"

    app: Mapped[str] = mapped_column(String(32), primary_key=True)
    key: Mapped[str] = mapped_column(String(64))
    origin: Mapped[Optional[str]] = mapped_column(String(512), index=True)
    name: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    joined_via: Mapped[Optional[str]] = mapped_column(String(22))
    admitted_at: Mapped[str] = mapped_column(String(20))
    head_seq: Mapped[Optional[int]]
    head_hash: Mapped[Optional[str]] = mapped_column(String(64))
    head_root: Mapped[Optional[str]] = mapped_column(String(64))
    replicated_seq: Mapped[int] = mapped_column(default=0)
    replicated_at: Mapped[Optional[str]] = mapped_column(String(20))
    replication_error: Mapped[Optional[str]] = mapped_column(String(128))
    metadata_at: Mapped[Optional[str]] = mapped_column(String(20))

    def __init__(self, app: str, key: str, admitted_at: str, origin: Optional[str] = None,
                 joined_via: Optional[str] = None):
        self.app = app
        self.key = key
        self.admitted_at = admitted_at
        self.origin = origin
        self.joined_via = joined_via
        self.replicated_seq = 0


class NetAppEntry(db.Model):
    __tablename__ = f"{PREFIX}app_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    app: Mapped[str] = mapped_column(String(32), index=True)
    seq: Mapped[int]
    hash: Mapped[str] = mapped_column(String(64))
    leaf: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(160), index=True)
    subject: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    content: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(String(128))

    __table_args__ = (UniqueConstraint("app", "seq"),)

    def __init__(self, app: str, seq: int, hash: str, leaf: str, kind: str, subject: Optional[str], content: str,
                 signature: str):
        self.app = app
        self.seq = seq
        self.hash = hash
        self.leaf = leaf
        self.kind = kind
        self.subject = subject
        self.content = content
        self.signature = signature


class NetNonce(db.Model):
    __tablename__ = f"{PREFIX}nonces"

    signer: Mapped[str] = mapped_column(String(22), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    ts: Mapped[str] = mapped_column(String(20), index=True)

    def __init__(self, signer: str, nonce: str, ts: str):
        self.signer = signer
        self.nonce = nonce
        self.ts = ts


class NetSource(db.Model):
    __tablename__ = f"{PREFIX}sources"

    node: Mapped[str] = mapped_column(String(22), primary_key=True)
    url: Mapped[str] = mapped_column(String(512))
    cursor: Mapped[int] = mapped_column(default=0)
    last_ok: Mapped[Optional[str]] = mapped_column(String(20))
    last_error: Mapped[Optional[str]] = mapped_column(String(128))
    failures: Mapped[int] = mapped_column(default=0)

    def __init__(self, node: str, url: str):
        self.node = node
        self.url = url
        self.cursor = 0
        self.failures = 0


class NetEvent(db.Model):
    __tablename__ = f"{PREFIX}events"

    event: Mapped[str] = mapped_column(String(64), primary_key=True)
    app: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    reason: Mapped[Optional[str]] = mapped_column(String(64))
    conflicting: Mapped[Optional[str]] = mapped_column(String(64))
    height: Mapped[Optional[int]]
    position: Mapped[Optional[int]]
    received_at: Mapped[str] = mapped_column(String(20), index=True)

    def __init__(self, event: str, app: str, status: str, received_at: str, reason: Optional[str] = None,
                 conflicting: Optional[str] = None):
        self.event = event
        self.app = app
        self.status = status
        self.received_at = received_at
        self.reason = reason
        self.conflicting = conflicting


class NetConsumed(db.Model):
    __tablename__ = f"{PREFIX}consumed"

    key: Mapped[str] = mapped_column(String(96), primary_key=True)
    event: Mapped[str] = mapped_column(String(64))
    height: Mapped[int]

    def __init__(self, key: str, event: str, height: int):
        self.key = key
        self.event = event
        self.height = height


MODELS = [NetObject, NetApp, NetAppEntry, NetNonce, NetSource, NetEvent, NetConsumed]


def bind(key):
    if not key: return
    for model in MODELS:
        if getattr(model, "__bind_key__", None) is None: model.set_bind(key)


if not EXECUTION:
    from webfluid.core.context import FluidContext
    from wf_peering.models import *
    ctx = FluidContext.try_current()
    _bind = ctx.fluid.config.get("PEERING_MODELS_DB_BIND") if ctx is not None and ctx.fluid is not None else None
    if _bind:
        set_bind(_bind)
        bind(_bind)
