from fastapi import APIRouter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webfluid import Fluid


def setup(app: "Fluid") -> APIRouter:
    api_router = APIRouter(prefix="/api")

    from fluid.api.health import handle_request as health
    api_router.get("/health")(health)

    from fluid.api.v1 import setup as setup_v1
    setup_v1(api_router, app)
    return api_router
