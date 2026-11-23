from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from functools import wraps

PRIVATE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }


def failures(handler):
    @wraps(handler)
    async def wrapper(*args, **kwargs):
        from fluid.exceptions import NetFailure
        from wf_peering.api.utils import error
        try: return await handler(*args, **kwargs)
        except NetFailure as exc: return error(exc.code, exc.status)
    return wrapper


def private(data, status: int = 200) -> JSONResponse:
    return JSONResponse(content=data, status_code=status, headers=PRIVATE)


async def node_request(request: Request):
    from wf_peering.api.utils import public
    from wf_peering.services import BindingService, IdentityService
    from fluid.utils.network import NetworkService
    return public(IdentityService.net_statement(await BindingService.network(), NetworkService.operator()))


async def challenge_request(request: Request):
    from wf_peering.api.utils import public
    from wf_peering.services import BindingService
    from fluid.utils.network import NetworkService
    return public(NetworkService.challenge(await BindingService.network()))


@failures
async def join_request(request: Request):
    from fluid.exceptions import NetFailure
    from fluid.utils.network import NetworkService
    data = NetworkService.parse(await request.body())
    if set(data) != { "join" }: raise NetFailure("INVALID_BODY")
    return private(await NetworkService.admit(data["join"]))


async def genesis_request(request: Request):
    from wf_peering.api.utils import public, error
    from wf_peering.services import BindingService
    binding = await BindingService.get()
    if binding is None: return error("NOT_READY", 503)
    return public({ "net": binding["net"], "genesis": binding["genesis"], "anchor": binding["anchor"] })


async def policy_request(request: Request):
    from wf_peering.api.utils import public, error
    from wf_peering.protocol import network
    from wf_peering.services import BindingService
    from fluid.utils.store import ObjectStore
    if not await BindingService.network(): return error("NOT_READY", 503)
    current, conflicts, _ = await ObjectStore.policy()
    return public({ "policy": current, "conflicts": conflicts,
                    "policies": await ObjectStore.objects(network.POLICY_CONTEXT) })


async def objects_request(request: Request):
    from wf_peering.api.utils import public, error, bounded
    from wf_peering.services import BindingService
    from fluid.utils.store import ObjectStore, PAGE
    net = await BindingService.network()
    if net is None: return error("NOT_READY", 503)
    after = bounded(request.query_params.get("after"), 0, 0, 2 ** 53 - 1)
    limit = bounded(request.query_params.get("limit"), PAGE, 1, PAGE)
    items = await ObjectStore.page(after, limit + 1)
    more = len(items) > limit
    items = items[:limit]
    return public({ "net": net, "objects": items, "next": items[-1]["cursor"] if items else after, "more": more })


async def members_request(request: Request):
    from wf_peering.api.utils import public, error
    from fluid.utils.store import ObjectStore
    members = await ObjectStore.membership()
    if members is None: return error("NOT_READY", 503)
    return public({
        "net": members.net, "primary": members.primary,
        "claim": "Members whose admission chain this master verified. One source, not proof of completeness.",
        "members": [{ key: value for key, value in member.to_dict().items() if key != "url" or member.role != "peer" }
                    for member in sorted(members.members.values(), key=lambda item: item.admitted_at)]
    })


@failures
async def heartbeat_request(request: Request):
    from wf_peering.protocol import network
    from fluid.utils.apps import AppRegistry
    from fluid.utils.network import NetworkService
    raw = await request.body()
    body, role, key = await NetworkService.authenticate(request.headers.get("x-wf-net-auth"), "POST",
                                                        request.url.path, raw)
    request_id = network.object_id(network.read_header(request.headers["x-wf-net-auth"]))
    return private(await AppRegistry.heartbeat(body, key, NetworkService.parse(raw), request_id))


@failures
async def attest_request(request: Request):
    from fluid.exceptions import NetFailure
    from fluid.utils.network import NetworkService
    from fluid.utils.store import ObjectStore
    raw = await request.body()
    body, role, key = await NetworkService.authenticate(request.headers.get("x-wf-net-auth"), "POST",
                                                        request.url.path, raw)
    items = NetworkService.parse(raw).get("attestations")
    if not isinstance(items, list) or len(items) > 100: raise NetFailure("INVALID_BODY")
    results = []
    for item in items:
        if not isinstance(item, dict) or item.get("key") != key:
            results.append({ "status": "SIGNER_NOT_SENDER" })
            continue
        oid, status = await ObjectStore.put(item, f"peer:{body['by']}")
        results.append({ "id": oid, "status": status })
    return private({ "results": results })


@failures
async def events_request(request: Request):
    from fluid.utils.chain import ChainService
    from fluid.utils.network import NetworkService
    raw = await request.body()
    body, role, key = await NetworkService.authenticate(request.headers.get("x-wf-net-auth"), "POST",
                                                        request.url.path, raw)
    return private(await ChainService.submit(NetworkService.parse(raw), key))


@failures
async def rotate_request(request: Request):
    from fluid.exceptions import NetFailure
    from fluid.utils.network import NetworkService
    from fluid.utils.store import ObjectStore
    raw = await request.body()
    body, role, key = await NetworkService.authenticate(request.headers.get("x-wf-net-auth"), "POST",
                                                        request.url.path, raw)
    rotation = NetworkService.parse(raw).get("rotation")
    if not isinstance(rotation, dict) or rotation.get("key") != key: raise NetFailure("SIGNER_NOT_SENDER", 403)
    oid, status = await ObjectStore.put(rotation, "self")
    if status not in ("stored", "duplicate"): raise NetFailure(f"ROTATION_{status}")
    return private({ "id": oid, "status": status })


async def operator_request(request: Request):
    from wf_peering.api.utils import public, error
    from wf_peering.services import BindingService
    from fluid.utils.operator import OperatorService
    if not await BindingService.network(): return error("NOT_READY", 503)
    return public(await OperatorService.document())


async def operators_request(request: Request):
    from wf_peering.api.utils import public, error
    from wf_peering.services import BindingService
    from fluid.utils.operator import OperatorService
    net = await BindingService.network()
    if not net: return error("NOT_READY", 503)
    return public({ "net": net, "operators": await OperatorService.latest(),
                    "claim": "Latest operator declaration this master knows per master; verify each signature." })


@failures
async def receipt_request(request: Request, event: str):
    from wf_peering.api.utils import public, error
    from fluid.utils.chain import ChainService
    if len(event) != 64 or any(c not in "0123456789abcdef" for c in event): return error("INVALID_EVENT")
    return public(await ChainService.receipt(event))


async def blocks_request(request: Request):
    from wf_peering.api.utils import public, bounded
    from wf_peering.protocol import network
    from fluid.utils.chain import ChainService
    from fluid.utils.store import ObjectStore
    start = bounded(request.query_params.get("from"), 1, 1, 2 ** 53 - 1)
    limit = bounded(request.query_params.get("limit"), 50, 1, 200)
    blocks = [item for item in await ChainService.blocks() if item["body"]["height"] >= start][:limit]
    witnesses = {}
    for item in await ObjectStore.objects(network.WITNESS_CONTEXT):
        witnesses.setdefault(item["body"]["block"], []).append(item)
    return public({ "blocks": [{ "block": item, "witnesses": witnesses.get(network.object_id(item), []) }
                               for item in blocks], "stats": await ChainService.stats() })


ROUTES = (
    ("GET", "/net/node", "240/minute", node_request),
    ("GET", "/net/challenge", "60/minute", challenge_request),
    ("POST", "/net/join", "30/minute", join_request),
    ("GET", "/net/genesis", "120/minute", genesis_request),
    ("GET", "/net/policy", "120/minute", policy_request),
    ("GET", "/net/objects", "240/minute", objects_request),
    ("GET", "/net/members", "60/minute", members_request),
    ("GET", "/net/operator", "120/minute", operator_request),
    ("GET", "/net/operators", "60/minute", operators_request),
    ("POST", "/net/heartbeat", "240/minute", heartbeat_request),
    ("POST", "/net/attest", "120/minute", attest_request),
    ("POST", "/net/events", "240/minute", events_request),
    ("POST", "/net/rotate", "10/minute", rotate_request),
    ("GET", "/net/receipts/{event}", "240/minute", receipt_request),
    ("GET", "/net/blocks", "120/minute", blocks_request)
)


def register(router: APIRouter, limit):
    for method, path, rate, handler in ROUTES:
        decorate = router.get if method == "GET" else router.post
        decorate(path)(limit(rate)(handler))
