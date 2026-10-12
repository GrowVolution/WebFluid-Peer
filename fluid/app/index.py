

async def handle_request():
    from wf_peering import peering, PEER_API
    return await peering.render_status(PEER_API)
