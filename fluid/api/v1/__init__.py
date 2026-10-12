from fastapi import APIRouter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webfluid import Fluid


def setup(router: APIRouter, app: "Fluid"):
    from wf_peering.api import register, route, observations_request
    from .sync import sync_request

    v1 = APIRouter(prefix="/v1")
    register(v1, app.limit)
    route(v1, app.limit, "/sync", "60/minute", sync_request)
    route(v1, app.limit, "/integrity/observations", "60/minute", observations_request)
    router.include_router(v1)
