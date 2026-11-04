from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from wf_peering.protocol import entries, merkle
from wf_peering.protocol.handshake import HELLO_CONTEXT, AUTH_CONTEXT, WELCOME_CONTEXT
from wf_peering.protocol.signing import Signer, verify, b64encode
from wf_peering.services.identity import NODE_CONTEXT
import asyncio, json, secrets


async def serve(app, port: int):
    import uvicorn
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical"))
    task = asyncio.create_task(server.serve())
    while not server.started: await asyncio.sleep(0.02)
    return server, task


class FakeHost:
    def __init__(self, origin: str):
        self.origin = origin
        self.signer = Signer.generate()
        self.items: list[dict] = []
        self.schema = 1
        self.fail_head = 0
        self.files: dict[str, bytes] = {}
        self.sockets: list = []
        self.override_head: dict | None = None

    def append(self, kind: str, body: dict, subject=None) -> dict:
        prev = self.items[-1]["hash"] if self.items else entries.GENESIS
        content = entries.make(len(self.items) + 1, prev, kind, kind.split(":")[0], body, subject=subject)
        value = entries.entry_hash(content)
        item = { "seq": content["seq"], "hash": value, "content": content,
                 "signature": entries.sign_hash(self.signer, entries.LEDGER_CONTEXT, value) }
        self.items.append(item)
        return item

    def rewrite(self, seq: int, body: dict):
        tail = self.items[seq - 1:]
        self.items = self.items[:seq - 1]
        first = tail[0]["content"]
        self.append(first["kind"], body, first["subject"])
        for item in tail[1:]:
            self.append(item["content"]["kind"], item["content"]["body"], item["content"]["subject"])

    def rotate_key(self):
        self.signer = Signer.generate()
        old = list(self.items)
        self.items = []
        for item in old:
            self.append(item["content"]["kind"], item["content"]["body"], item["content"]["subject"])

    def head(self) -> dict:
        if self.override_head: return self.override_head
        size = len(self.items)
        tree = merkle.root([entries.entry_leaf(item["content"]) for item in self.items])
        head = entries.head(size, self.items[-1]["hash"] if self.items else entries.GENESIS, tree,
                            entries.utc_now(), self.origin, 1, self.schema)
        return { "head": head, "key": self.signer.public_key, "signer": self.signer.fingerprint,
                 "signature": self.signer.sign(entries.HEAD_CONTEXT, head) }

    async def head_route(self, request):
        if self.fail_head > 0:
            self.fail_head -= 1
            return JSONResponse({ "detail": "busy" }, status_code=503)
        return JSONResponse(self.head())

    async def ledger_route(self, request):
        start = int(request.query_params.get("from", 1))
        limit = int(request.query_params.get("limit", 100))
        page = self.items[start - 1:start - 1 + limit]
        return JSONResponse({ "entries": page, "next": start + len(page) })

    async def node_route(self, request):
        statement = { "node": self.signer.fingerprint, "key": self.signer.public_key, "role": "host",
                      "url": self.origin, "host": self.origin, "protocol": 1, "schema": self.schema,
                      "software": "fake", "boot": "b", "started_at": entries.utc_now(), "ts": entries.utc_now() }
        return JSONResponse({ "statement": statement, "signature": self.signer.sign(NODE_CONTEXT, statement) })

    async def empty_route(self, request):
        return JSONResponse({ "peers": [], "checkpoints": [] })

    async def checkpoint_route(self, request):
        return JSONResponse({ "detail": "NO_CHECKPOINT" }, status_code=404)

    async def file_route(self, request):
        data = self.files.get(request.url.path)
        if data is None: return Response(status_code=404)
        return Response(data, media_type="application/javascript")

    async def socket(self, websocket):
        await websocket.accept()
        challenge = b64encode(secrets.token_bytes(16))
        hello = { "node": self.signer.fingerprint, "key": self.signer.public_key, "origin": self.origin,
                  "challenge": challenge, "protocol": 1, "schema": self.schema, "boot": "b", "ts": entries.utc_now() }
        await websocket.send_text(json.dumps({ "type": "hello", "statement": hello,
                                               "signature": self.signer.sign(HELLO_CONTEXT, hello) }))
        auth = json.loads(await websocket.receive_text())
        statement = auth["statement"]
        assert statement["challenge"] == challenge
        assert verify(statement["key"], AUTH_CONTEXT, statement, auth["signature"])
        welcome = { "nonce": statement["nonce"], "node": statement["node"], "host": self.signer.fingerprint,
                    "ts": entries.utc_now() }
        await websocket.send_text(json.dumps({ "type": "welcome", "statement": welcome,
                                               "signature": self.signer.sign(WELCOME_CONTEXT, welcome) }))
        self.sockets.append(websocket)
        try:
            while True:
                message = json.loads(await websocket.receive_text())
                if message["type"] == "range":
                    start = message["from"]
                    page = self.items[start - 1:start - 1 + message.get("limit", 100)]
                    await websocket.send_text(json.dumps({ "type": "entries", "entries": page,
                                                           "more": start - 1 + len(page) < len(self.items) }))
                elif message["type"] == "heartbeat":
                    await websocket.send_text(json.dumps({ "type": "heartbeat", "head": {
                        "seq": len(self.items), "hash": self.items[-1]["hash"] if self.items else entries.GENESIS } }))
        except Exception:
            pass
        finally:
            if websocket in self.sockets: self.sockets.remove(websocket)

    async def push(self, item: dict):
        for websocket in list(self.sockets):
            await websocket.send_text(json.dumps({ "type": "entry", "entry": item }))

    def app(self) -> Starlette:
        return Starlette(routes=[
            Route("/peering/api/v1/ledger/head", self.head_route),
            Route("/peering/api/v1/ledger", self.ledger_route),
            Route("/peering/api/v1/node", self.node_route),
            Route("/peering/api/v1/peers", self.empty_route),
            Route("/peering/api/v1/checkpoints/latest", self.checkpoint_route),
            Route("/users/static/js/e2ee.js", self.file_route),
            WebSocketRoute("/peering/ws/peer", self.socket)
        ])
