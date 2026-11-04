from webfluid import Fluid


def prepare_fluid() -> Fluid:
    _fluid = Fluid(__name__)

    from wf_peering import peering
    from .utils.role import PeerRole
    peering.expand_fluid(_fluid, role=PeerRole(_fluid.config["APP_CONFIG"].get("version")))

    from .api import setup as setup_api
    _fluid.include_router(setup_api(_fluid))

    from .app import app_router
    _fluid.include_router(app_router)

    from wf_peering.settings import settings
    if settings.schedule:
        from .jobs import setup as setup_jobs
        setup_jobs()

    return _fluid
