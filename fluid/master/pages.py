from fastapi import Request
import re

_APP = re.compile(r"^app1\.[A-Za-z0-9_-]{22}$")
SCRIPT_TEXTS = ("NET_DASH_RESULTS", "NET_DASH_UPDATED", "NET_DASH_STALE", "NET_ACTIVE", "NET_INACTIVE")


class Pages:
    version = "0"


async def _context(request: Request, page: str) -> dict:
    from webfluid.core.ext import babel
    from webfluid.extensions.babel import get_locale
    from wf_peering.services import IdentityService
    from wf_peering.settings import settings
    from wf_peering.role import current
    from fluid.utils import legal
    from fluid.utils.status import StatusService
    from . import ASSETS
    status = await StatusService.summary()
    role = current()
    data = legal.context(request.app.config)
    return {
        "lang": get_locale().language, "page": page, "assets": ASSETS, "version": Pages.version,
        "texts": { key: await babel.agettext(key) for key in SCRIPT_TEXTS },
        "node": IdentityService.node_id(), "net": status.get("network"), "status": status,
        "role_label": await babel.agettext("NET_UI_ROLE_" + role.topology.label.upper()),
        "debug": settings.debug, "legal": data, "legal_missing": data["missing"] if settings.debug else [],
        "software": role.software
    }


async def dashboard(request: Request):
    from fluid.utils.apps import AppRegistry
    from fluid.utils.status import StatusService
    query = (request.query_params.get("q") or "")[:64]
    inactive = request.query_params.get("inactive") == "1"
    try: page = max(1, int(request.query_params.get("page") or 1))
    except ValueError: page = 1
    context = await _context(request, "apps")
    results = await AppRegistry.search(query or None, page, 25, inactive) if context["net"] else \
        { "items": [], "total": 0, "page": 1, "pages": 1 }
    return await request.app.render("net/dashboard.html", query=query, inactive=inactive, results=results,
                                    trust=await StatusService.network_trust(), **context)


async def detail(request: Request, app: str):
    from fluid.utils.apps import AppRegistry
    from fluid.utils.store import ObjectStore
    from wf_peering.protocol import network
    context = await _context(request, "apps")
    data, heads = None, []
    if _APP.match(app) and context["net"]:
        data = await AppRegistry.detail(app)
        newest = {}
        for item in await ObjectStore.objects(network.ATTEST_CONTEXT, app):
            body = item["body"]
            if body["kind"] != "head": continue
            if body["by"] not in newest or body["observed_at"] > newest[body["by"]]["at"]:
                newest[body["by"]] = { "by": body["by"], "seq": body["head"]["seq"], "root": body["head"]["root"],
                                       "at": body["observed_at"] }
        heads = sorted(newest.values(), key=lambda item: item["by"])
    return await request.app.render("net/app.html", app=app if _APP.match(app) else "–", detail=data, heads=heads,
                                    **context)


async def imprint(request: Request):
    return await request.app.render("net/imprint.html", **await _context(request, "imprint"))


async def privacy(request: Request):
    return await request.app.render("net/privacy.html", **await _context(request, "privacy"))
