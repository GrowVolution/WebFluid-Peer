from fastapi import APIRouter, Request
import re

from .net import failures

_APP = re.compile(r"^app1\.[A-Za-z0-9_-]{22}$")


async def search_request(request: Request):
    from wf_peering.api.utils import public, error, bounded
    from wf_peering.services import BindingService, IdentityService
    from fluid.utils.apps import AppRegistry
    if not await BindingService.network(): return error("NOT_READY", 503)
    query = request.query_params.get("q")
    if query is not None and len(query) > 64: return error("QUERY_TOO_LONG")
    result = await AppRegistry.search(query, bounded(request.query_params.get("page"), 1, 1, 10000),
                                      bounded(request.query_params.get("size"), 25, 1, 50),
                                      request.query_params.get("inactive") in ("1", "true"))
    result["responder"] = IdentityService.node_id()
    return public(result)


@failures
async def detail_request(request: Request, app: str):
    from wf_peering.api.utils import public, error
    from wf_peering.services import IdentityService
    from fluid.utils.apps import AppRegistry
    if not _APP.match(app): return error("INVALID_APP")
    data = await AppRegistry.detail(app)
    if data is None: return error("UNKNOWN_APP", 404)
    data["responder"] = IdentityService.node_id()
    return public(data)


@failures
async def evidence_request(request: Request, app: str):
    from wf_peering.api.utils import public, error
    from fluid.utils.apps import AppRegistry
    from fluid.utils.store import ObjectStore
    if not _APP.match(app): return error("INVALID_APP")
    members = await ObjectStore.membership()
    if members is None or members.app(app) is None: return error("UNKNOWN_APP", 404)
    return public(await AppRegistry.bundle(app))


async def ledger_request(request: Request, app: str):
    from wf_peering.api.utils import public, error, bounded, valid_subject
    from fluid.utils.apps import AppRegistry
    if not _APP.match(app): return error("INVALID_APP")
    subject = request.query_params.get("subject")
    if not valid_subject(subject): return error("INVALID_SUBJECT")
    items = await AppRegistry.entries(app, bounded(request.query_params.get("from"), 1, 1, 2 ** 53 - 1),
                                      bounded(request.query_params.get("limit"), 100, 1, 500), subject)
    return public({ "app": app, "entries": items, "source": "master-replica" })


ROUTES = (
    ("/apps", "120/minute", search_request),
    ("/apps/{app}", "120/minute", detail_request),
    ("/apps/{app}/evidence", "120/minute", evidence_request),
    ("/apps/{app}/ledger", "60/minute", ledger_request)
)


def register(router: APIRouter, limit):
    for path, rate, handler in ROUTES:
        router.get(path)(limit(rate)(handler))
