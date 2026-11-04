from pathlib import Path
import os, pytest, pytest_asyncio, shutil, sys, tempfile

SOURCE = Path(__file__).resolve().parents[1]

ROOT = Path(tempfile.mkdtemp(prefix="peering-peer-"))

os.environ.setdefault("PEERING_TEST_HOST", "http://127.0.0.1:8591")

MY_CONFIG = '''class MyConfig:
    BASE_URL = "http://127.0.0.1:8571"
    PEERING_HOST = {host!r}
    PEERING_PUBLIC_URL = "http://127.0.0.1:8571"
    PEERING_TRUSTED_REFERENCES = {{}}
    PEERING_SCHEDULE = False
    PEERING_ALLOW_INSECURE = True
    PEERING_KEY_FILE = {key!r}
    PEERING_CHECKPOINT_GRACE = 2
    PEERING_SYNC_ATTEMPTS = 2
    PEERING_REQUEST_TIMEOUT = 5
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
'''


def _build():
    shutil.copy(SOURCE / "main.py", ROOT / "main.py")
    shutil.copytree(SOURCE / "fluid", ROOT / "fluid", ignore=shutil.ignore_patterns("__pycache__", "_my_config.py"))
    (ROOT / "fluid" / "_my_config.py").write_text(MY_CONFIG.format(
        host=os.environ["PEERING_TEST_HOST"], key=str(ROOT / "keys" / "node.key")
    ), encoding="utf-8")


_build()
os.environ.update({
    "SECRET_KEY": "peering-test-secret",
    "EXT_SQLALCHEMY": "1",
    "EXT_SCHEDULING": "1",
    "EXT_BABEL": "1",
    "WF_PROCESSING": "1",
    "DATABASE_URI": f"sqlite:///{(ROOT / 'test.db').as_posix()}"
})
os.environ.pop("WF_ADDITIVES", None)
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)


def create_tables(db):
    for key in db.bind_keys:
        db.Model.metadata.create_all(db.get_bind(key).sync_engine)


@pytest_asyncio.fixture(scope="session")
async def fluid():
    from main import prepare_fluid
    from webfluid.core.ext import db
    app = prepare_fluid()
    create_tables(db)
    await app._lifecycle.run_startup()
    create_tables(db)
    from wf_peering.services import UptimeService
    await UptimeService.boot()
    yield app


@pytest_asyncio.fixture(scope="session")
async def client(fluid):
    import httpx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fluid), base_url="http://testserver") as c:
        yield c


@pytest.fixture(scope="session")
def root():
    return ROOT
