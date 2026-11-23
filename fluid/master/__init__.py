from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from jinja2 import FileSystemLoader, PrefixLoader
from pathlib import Path
from typing import TYPE_CHECKING
import hashlib

if TYPE_CHECKING:
    from webfluid import Fluid

ROOT = Path(__file__).resolve().parent
ASSETS = "/net/static"


def version() -> str:
    hasher = hashlib.sha256()
    for path in sorted((ROOT / "static").rglob("*")):
        if path.is_file(): hasher.update(path.read_bytes())
    return hasher.hexdigest()[:16]


def setup(fluid: "Fluid"):
    fluid.static_files.add(ASSETS, ROOT / "static", "net_static")
    fluid.static_prefixes.add(ASSETS)
    fluid.add_template_loader(PrefixLoader({"net": FileSystemLoader(ROOT / "templates")}))

    from webfluid.core.ext import babel
    from ..i18n import translations
    babel.update_translations("messages", translations)

    from .pages import Pages, dashboard, detail, imprint, privacy
    Pages.version = version()
    router = APIRouter(default_response_class=HTMLResponse)
    router.get("/")(dashboard)
    router.get("/apps/{app}")(detail)
    router.get("/imprint")(imprint)
    router.get("/privacy")(privacy)
    fluid.include_router(router)
