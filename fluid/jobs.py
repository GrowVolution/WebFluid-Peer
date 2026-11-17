from webfluid.core.ext import scheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from wf_peering.jobs import guarded
from wf_peering.settings import settings
from datetime import datetime, timedelta, UTC

FIRST_OBSERVATION = timedelta(seconds=30)
FIRST_ROOT_CHECK = timedelta(seconds=90)
CATCH_UP = timedelta(seconds=60)


def setup():
    now = datetime.now(UTC)
    scheduler.add_job(observe, IntervalTrigger(seconds=settings.integrity_interval),
                      next_run_time=now + FIRST_OBSERVATION, misfire_grace_time=None)
    hour, minute = settings.sync_time
    scheduler.add_job(daily_sync, CronTrigger(hour=hour, minute=minute, timezone="UTC"),
                      misfire_grace_time=600, coalesce=True)
    scheduler.add_job(catch_up, DateTrigger(run_date=now + CATCH_UP), misfire_grace_time=None)
    scheduler.add_job(check_root, IntervalTrigger(seconds=settings.integrity_interval),
                      next_run_time=now + FIRST_ROOT_CHECK, misfire_grace_time=None)


@guarded("observe")
async def observe():
    from fluid.utils import observe as observation
    await observation.run()


@guarded("sync")
async def daily_sync():
    from fluid.utils.sync import FullSync
    await FullSync.run("daily", datetime.now(UTC).strftime("%Y-%m-%d"))


@guarded("root-check")
async def check_root():
    from fluid.utils.sync import FullSync
    await FullSync.check_root()


@guarded("catch-up")
async def catch_up():
    from fluid.utils.sync import FullSync
    if await FullSync.due(): await FullSync.run("startup")
