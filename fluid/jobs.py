from webfluid.core.ext import scheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from wf_peering.jobs import guarded
from wf_peering.settings import settings
from datetime import datetime, timedelta, UTC

FIRST_REPLICATION = timedelta(seconds=20)


def setup(topology):
    now = datetime.now(UTC)
    first = min(FIRST_REPLICATION, timedelta(seconds=settings.integrity_interval))
    scheduler.add_job(replicate, IntervalTrigger(seconds=settings.integrity_interval),
                      next_run_time=now + first, misfire_grace_time=None, coalesce=True)
    if topology.role == "master":
        scheduler.add_job(blocks, IntervalTrigger(seconds=settings.block_interval), misfire_grace_time=None,
                          coalesce=True)
        scheduler.add_job(policy, DateTrigger(run_date=now + timedelta(seconds=15)), misfire_grace_time=None)
        scheduler.add_job(operator, IntervalTrigger(hours=24), next_run_time=now + timedelta(seconds=20),
                          misfire_grace_time=None, coalesce=True)


@guarded("replicate")
async def replicate():
    from wf_peering.services import BindingService
    from fluid.utils.apps import AppRegistry
    from fluid.utils.link import UpstreamLink
    if not await BindingService.network(): return
    await AppRegistry.ensure_rows()
    for app in await AppRegistry.active_apps(): await AppRegistry.replicate(app)
    if settings.is_peer: await UpstreamLink.submit()


@guarded("blocks")
async def blocks():
    from wf_peering.services import BindingService
    from fluid.utils.chain import ChainService
    if not await BindingService.network(): return
    await ChainService.close_block()
    await ChainService.witness()


@guarded("operator")
async def operator():
    from fluid.utils.operator import OperatorService
    await OperatorService.maintain()


@guarded("policy")
async def policy():
    from fluid.utils.network import NetworkService
    from wf_peering.role import current
    await NetworkService.maintain_policy(current().policy)
