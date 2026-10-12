from fastapi import APIRouter
from fastapi.responses import HTMLResponse

app_router = APIRouter(default_response_class=HTMLResponse)

from fluid.app.index import handle_request as index
app_router.get("/")(index)
