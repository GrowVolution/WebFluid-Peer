from webfluid.core.ext import scheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime, UTC

from wf_peering.services.settings import settings
from wf_peering.services.tasks import guarded


@guarded("observe")
async def observe():
    from . import observe as observation
    await observation.run()


@guarded("sync")
async def daily_sync():
    from .sync import FullSync
    await FullSync.run("daily", datetime.now(UTC).strftime("%Y-%m-%d"))


def setup():
    scheduler.add_job(observe, IntervalTrigger(seconds=settings.integrity_interval))
    hour, minute = settings.sync_time
    scheduler.add_job(daily_sync, CronTrigger(hour=hour, minute=minute, timezone="UTC"),
                      misfire_grace_time=600, coalesce=True)
