from fastapi import APIRouter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webfluid import Fluid


def setup(router: APIRouter, app: "Fluid", topology):
    from .status import status_request

    v1 = APIRouter(prefix="/v1")
    v1.get("/status")(app.limit("60/minute")(status_request))
    if topology.role == "master":
        from . import apps, net
        net.register(v1, app.limit)
        apps.register(v1, app.limit)
    router.include_router(v1)
