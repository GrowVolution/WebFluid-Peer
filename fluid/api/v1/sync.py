from fastapi import Request


async def sync_request(request: Request):
    from wf_peering.api.utils import public
    from wf_peering.services.settings import settings
    from wf_peering.services.status import next_at
    from fluid.services.sync import FullSync, HostLink
    return public({
        "role": settings.role,
        "next_full_sync": next_at(*settings.sync_time),
        "next_checkpoint": next_at(*settings.checkpoint_time),
        "runs": await FullSync.runs(),
        "link": HostLink.snapshot()
    })
