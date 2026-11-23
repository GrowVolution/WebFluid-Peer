from webfluid import Fluid


def prepare_fluid() -> Fluid:
    _fluid = Fluid(__name__)

    from webfluid.core.constants import DEBUG
    from .utils.topology import resolve
    topology = resolve(_fluid.config, DEBUG)

    from wf_peering import peering
    from .models import bind
    from .utils.role import NetRole
    config = _fluid.config
    policy = {
        "inactive_days": int(config.get("PEERING_INACTIVE_DAYS") or 30),
        "attest_max_age": int(config.get("PEERING_ATTEST_MAX_AGE") or 26 * 3600),
        "min_groups": int(config.get("PEERING_MIN_GROUPS") or 2)
    }
    role = NetRole(topology, config["APP_CONFIG"].get("version"), policy, config.get("NETWORK_NAME") or "webfluid",
                   int(config.get("PEERING_METADATA_RETENTION_DAYS") or 90))
    peering.expand_fluid(_fluid, role=role)
    bind(config.get("PEERING_MODELS_DB_BIND"))

    from wf_peering.settings import settings
    from .utils.apps import AppRegistry
    from .utils.chain import ChainService
    from .utils.network import NetworkService
    from .utils.operator import OperatorService
    from .utils.legal import node_operator
    settings.upstream = topology.upstream
    NetworkService.configure(topology, node_operator(config) if topology.role == "master" else None)
    OperatorService.configure(config, topology)
    AppRegistry.operators = dict(config.get("PEERING_OPERATORS") or {})
    ChainService.operators = AppRegistry.operators

    from .api import setup as setup_api
    _fluid.include_router(setup_api(_fluid, topology))

    if topology.role == "master":
        from .master import setup as setup_frontend
        from .utils.legal import validate
        validate(config, DEBUG)
        setup_frontend(_fluid)

    if settings.schedule:
        from .jobs import setup as setup_jobs
        setup_jobs(topology)

    return _fluid
