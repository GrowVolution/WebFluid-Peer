from webfluid import Fluid


def prepare_fluid() -> Fluid:
    app = Fluid(__name__)

    from wf_peering import peering
    from fluid.utils.role import PeerRole
    peering.expand_fluid(app, role=PeerRole(app.config["APP_CONFIG"].get("version")))

    from fluid.api import setup as setup_api
    app.include_router(setup_api(app))

    from fluid.app import app_router
    app.include_router(app_router)

    from wf_peering.settings import settings
    if settings.schedule:
        from fluid.jobs import setup as setup_jobs
        setup_jobs()

    return app


if __name__ == "__main__":
    fluid = prepare_fluid()
    fluid.mix()
