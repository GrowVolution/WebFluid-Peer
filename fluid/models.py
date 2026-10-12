from webfluid.core.constants import EXECUTION

if not EXECUTION:
    from webfluid.core.context import FluidContext
    from wf_peering.models import *
    ctx = FluidContext.try_current()
    bind = ctx.fluid.config.get("PEERING_MODELS_DB_BIND") if ctx is not None and ctx.fluid is not None else None
    if bind: set_bind(bind)
