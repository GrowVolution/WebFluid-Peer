from fastapi import Request


async def status_request(request: Request):
    from wf_peering.api.utils import public
    from fluid.utils.status import StatusService
    return public(await StatusService.summary())
