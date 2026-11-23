from pathlib import Path
import httpx, json, os, pytest, shutil, socket, subprocess, sys, tempfile, time

pytestmark = pytest.mark.skipif(os.environ.get("PEERING_E2E") != "1", reason="set PEERING_E2E=1 to run the "
                                                                                  "multi-process network test")

REPO = Path(__file__).resolve().parents[2]
ADDITIVE = Path(os.environ.get("PEERING_ADDITIVE") or REPO.parent / "wf-site" / "additives" / "peering")
TIMEOUT = float(os.environ.get("PEERING_E2E_TIMEOUT") or 120)

LAUNCH = '''import os, sys
sys.path.insert(0, os.getcwd())
import wf_peering.models
from main import prepare_fluid
from webfluid.core.ext import db
app = prepare_fluid()
for key in db.bind_keys:
    db.Model.metadata.create_all(db.get_bind(key).sync_engine)
app.mix()
'''

ROUTES = '''import os, sys, json
sys.path.insert(0, os.getcwd())
from main import prepare_fluid
app = prepare_fluid()
paths = []
def walk(routes, prefix=""):
    for route in routes:
        context = getattr(route, "include_context", None)
        if context is not None: walk(context.included_router.routes, prefix + context.prefix)
        else: paths.append(prefix + getattr(route, "path", ""))
walk(app.routes)
static = [str(prefix) for prefix in app.static_prefixes._prefixes] if hasattr(app.static_prefixes, "_prefixes") else []
print(json.dumps({ "paths": sorted(set(paths)), "static": static }))
'''

APP_MAIN = '''from webfluid import Fluid
from fastapi.responses import Response

SERVED = {"count": 0}


def prepare_fluid() -> Fluid:
    fluid = Fluid(__name__)

    @fluid.get("/test/selective.js")
    async def selective():
        SERVED["count"] += 1
        body = b"console.log(1)\\n" if SERVED["count"] % 2 else b"console.log(2)\\n"
        return Response(body, media_type="text/javascript")

    @fluid.post("/test/record")
    async def record(payload: dict):
        from webfluid.core.ext import events
        return await events.request("peering_record", payload)

    @fluid.post("/test/artifact")
    async def artifact(payload: dict):
        from webfluid.core.ext import events
        return await events.request("peering_artifact", payload)

    @fluid.post("/test/event")
    async def event(payload: dict):
        from webfluid.core.ext import events
        return await events.request("peering_event", payload)

    return fluid
'''

APP_CONFIG = '''from webfluid.core.config import register_config


@register_config(10)
class Config:
    APP_CONFIG = {{"title": {title!r}, "version": "1.0.0"}}
    APP_FRONTEND = None
    BASE_URL = {url!r}
    PEERING_MASTER_URL = {master!r}
    PEERING_ALLOW_INSECURE = True
    PEERING_NET_INTERVAL = 2
    PEERING_INTEGRITY_INTERVAL = 30
    PEERING_REQUEST_TIMEOUT = 5
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    BABEL_SUPPORTED_LOCALES = ["en", "de"]
'''


def legal(name: str) -> dict:
    return {
        "operator": { "name": name, "form": "natural_person", "address": ["Beispielweg 1", "12345 Beispielstadt"],
                      "country": "DE", "commercial": False, "email": "kontakt@example.org" },
        "privacy": { "legal_basis": "art6_1_f", "hosting": "Beispiel: eigener Server", "proxy_logs_days": 0,
                     "backups_days": None, "supervisory_authority": "Beispiel-Aufsichtsbehörde",
                     "transfers": False, "dpo": False }
    }


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def environment(root: Path, port: int, app: bool, processing: bool = True) -> dict:
    keep = { key: value for key, value in os.environ.items()
             if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA",
                                "PATHEXT", "COMSPEC", "WINDIR", "PYTHONPATH", "VIRTUAL_ENV") }
    keep.update({
        "SECRET_KEY": "e2e-secret", "EXT_SQLALCHEMY": "1", "EXT_SCHEDULING": "1", "EXT_BABEL": "1",
        "WF_PROCESSING": "1" if processing else "0", "IN_EXECUTION": "1", "SERVER_HOST": "127.0.0.1", "SERVER_PORT": str(port),
        "DATABASE_URI": f"sqlite:///{(root / 'node.db').as_posix()}", "PYTHONUNBUFFERED": "1"
    })
    if app: keep.update({ "EXT_EVENTS": "1", "WF_ADDITIVES": "1", "peering": "1" })
    return keep


class Node:
    def __init__(self, name: str, root: Path, port: int, app: bool, processing: bool = True):
        self.name, self.root, self.port, self.app, self.processing = name, root, port, app, processing
        self.process = None
        self.url = f"http://127.0.0.1:{port}"

    def start(self):
        log = open(self.root / "node.log", "ab")
        self.process = subprocess.Popen([sys.executable, "launch.py"], cwd=self.root, stdout=log,
                                        stderr=subprocess.STDOUT,
                                        env=environment(self.root, self.port, self.app, self.processing))
        return self

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=15)
            except subprocess.TimeoutExpired: self.process.kill()
        self.process = None

    def tail(self) -> str:
        path = self.root / "node.log"
        return path.read_text(encoding="utf-8", errors="replace")[-3000:] if path.is_file() else ""


def peer_node(base: Path, name: str, port: int, config: dict) -> Node:
    root = base / name
    root.mkdir()
    shutil.copy(REPO / "main.py", root / "main.py")
    shutil.copytree(REPO / "fluid", root / "fluid", ignore=shutil.ignore_patterns("__pycache__", "_my_config.py"))
    values = dict({ "PEERING_ALLOW_INSECURE": True, "PEERING_NET_INTERVAL": 2, "PEERING_INTEGRITY_INTERVAL": 4,
                    "PEERING_BLOCK_INTERVAL": 2, "PEERING_REQUEST_TIMEOUT": 5, "RATELIMIT_ENABLED": False,
                    "SESSION_COOKIE_SECURE": False, "PEERING_KEY_FILE": str(root / "keys" / "node.key") }, **config)
    body = "".join(f"    {key} = {value!r}\n" for key, value in values.items())
    (root / "fluid" / "_my_config.py").write_text(f"class MyConfig:\n{body}", encoding="utf-8")
    (root / "launch.py").write_text(LAUNCH, encoding="utf-8")
    (root / "routes.py").write_text(ROUTES, encoding="utf-8")
    return Node(name, root, port, False, config.get("IS_MASTER") is True)


def app_node(base: Path, name: str, port: int, master: str) -> Node:
    root = base / name
    (root / "fluid").mkdir(parents=True)
    (root / "additives").mkdir()
    (root / "additives" / "__init__.py").write_text("", encoding="utf-8")
    shutil.copytree(ADDITIVE, root / "additives" / "peering",
                    ignore=shutil.ignore_patterns("tests", "keys", "__pycache__", ".git", ".idea", ".pytest_cache"))
    (root / "fluid" / "__init__.py").write_text("", encoding="utf-8")
    (root / "fluid" / "config.py").write_text(APP_CONFIG.format(title=name, url=f"http://127.0.0.1:{port}",
                                                                master=master), encoding="utf-8")
    (root / "main.py").write_text(APP_MAIN, encoding="utf-8")
    (root / "launch.py").write_text(LAUNCH, encoding="utf-8")
    return Node(name, root, port, True)


def get(url: str, default=None):
    try:
        response = httpx.get(url, timeout=5)
        return response.json() if response.status_code == 200 else default
    except (httpx.HTTPError, ValueError):
        return default


def wait(label: str, check, nodes: list, timeout: float = TIMEOUT):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = check()
            if last: return last
        except Exception as exc:
            last = repr(exc)
        time.sleep(1)
    logs = "\n".join(f"--- {node.name}\n{node.tail()}" for node in nodes)
    raise AssertionError(f"timed out waiting for {label}; last={last!r}\n{logs}")


def evaluate(bundle: dict, anchor: str, operators: dict) -> dict:
    from wf_peering.protocol import evidence
    return evidence.evaluate(bundle, anchor, operators)


@pytest.fixture(scope="module")
def network():
    if not ADDITIVE.is_dir(): pytest.skip(f"peering Additive not found at {ADDITIVE}")
    base = Path(tempfile.mkdtemp(prefix="peering-e2e-"))
    ports = { name: free_port() for name in ("primary", "second", "third", "app1", "app2") }
    urls = { name: f"http://127.0.0.1:{port}" for name, port in ports.items() }
    nodes = {
        "primary": peer_node(base, "primary", ports["primary"], { "IS_MASTER": True, "JOIN_MASTER": None,
                                                                  "PEERING_PUBLIC_URL": urls["primary"],
                                                                  "NETWORK_NAME": "e2e",
                                                                  "LEGAL": legal("Primary Beispiel") }),
        "second": peer_node(base, "second", ports["second"], { "IS_MASTER": True, "JOIN_MASTER": urls["primary"],
                                                               "PEERING_PUBLIC_URL": urls["second"],
                                                               "PEERING_INACTIVE_DAYS": 1,
                                                               "LEGAL": legal("Secondary Beispiel") }),
        "third": peer_node(base, "third", ports["third"], { "IS_MASTER": True, "JOIN_MASTER": urls["second"],
                                                            "PEERING_PUBLIC_URL": urls["third"],
                                                            "LEGAL": legal("Third Beispiel") }),
        "peer": peer_node(base, "peer", 0, { "JOIN_MASTER": urls["second"] }),
        "app1": app_node(base, "app1", ports["app1"], urls["primary"]),
        "app2": app_node(base, "app2", ports["app2"], urls["third"])
    }
    nodes["peer"].url = None
    started = []
    try:
        for name in ("primary", "second", "third", "peer", "app1", "app2"):
            started.append(nodes[name].start())
            if name in ("primary", "second"): time.sleep(3)
        yield { "nodes": nodes, "urls": urls, "base": base }
    finally:
        for node in reversed(started): node.stop()
        if os.environ.get("PEERING_E2E_KEEP") != "1": shutil.rmtree(base, ignore_errors=True)


def test_network_forms_and_converges(network):
    nodes, urls = network["nodes"], network["urls"]
    everyone = list(nodes.values())
    genesis = wait("primary genesis", lambda: get(f"{urls['primary']}/api/v1/net/genesis"), everyone)
    net = genesis["net"]
    assert genesis["anchor"] == "founded"
    for name in ("second", "third"):
        status = wait(f"{name} joined", lambda name=name: (get(f"{urls[name]}/api/v1/status") or {}).get("network")
                      == net and get(f"{urls[name]}/api/v1/status"), everyone)
        assert status["topology"] == "secondary" and status["anchor"] == "tofu"
    members = wait("all members known to the primary", lambda: (lambda data: data if data and
                   { member["role"] for member in data["members"] } >= { "master", "peer", "app" }
                   and len([m for m in data["members"] if m["role"] == "app"]) == 2
                   and len([m for m in data["members"] if m["role"] == "master"]) == 3 else None)(
        get(f"{urls['primary']}/api/v1/net/members")), everyone)
    peer = next(member for member in members["members"] if member["role"] == "peer")
    assert "url" not in peer or peer["url"] is None
    nodes_by_url = { name: get(f"{urls[name]}/api/v1/net/node")["body"]["by"] for name in ("primary", "second", "third") }
    network["ids"] = dict(nodes_by_url, peer=peer["node"], net=net)

    apps = wait("apps visible on every master", lambda: all(
        len((get(f"{urls[name]}/api/v1/apps") or {}).get("items") or []) == 2 for name in ("primary", "second", "third")
    ) and get(f"{urls['primary']}/api/v1/apps"), everyone)
    by_origin = { item["origin"]: item["app"] for item in apps["items"] }
    assert set(by_origin) == { urls["app1"], urls["app2"] }
    network["apps"] = { "app1": by_origin[urls["app1"]], "app2": by_origin[urls["app2"]] }

    def converged():
        heads = []
        for name in ("primary", "second", "third"):
            items = { item["app"]: item.get("head") for item in (get(f"{urls[name]}/api/v1/apps") or {}).get("items", []) }
            heads.append(items)
        return heads[0] if heads[0] and all(item == heads[0] and all(head for head in item.values()) for item in heads) \
            else None

    wait("same app heads on all masters", converged, everyone)


def test_default_peer_has_no_inbound_surface(network):
    root = network["nodes"]["peer"].root
    result = subprocess.run([sys.executable, "routes.py"], cwd=root, capture_output=True, text=True, timeout=120,
                            env=environment(root, 0, False, False))
    assert result.returncode == 0, result.stderr
    inventory = json.loads(result.stdout.strip().splitlines()[-1])
    paths = set(inventory["paths"])
    assert paths == { "/api/health", "/api/v1/status" }, paths
    assert not any("wf-peering" in prefix for prefix in inventory["static"])
    master = subprocess.run([sys.executable, "routes.py"], cwd=network["nodes"]["primary"].root, capture_output=True,
                            text=True, timeout=120, env=environment(network["nodes"]["primary"].root, 0, False))
    master_paths = set(json.loads(master.stdout.strip().splitlines()[-1])["paths"])
    assert { "/api/v1/net/join", "/", "/imprint", "/privacy" } <= master_paths
    urls = network["urls"]
    assert "Primary Beispiel" in httpx.get(f"{urls['primary']}/imprint", timeout=10).text
    assert "Secondary Beispiel" in httpx.get(f"{urls['second']}/imprint", timeout=10).text
    policy = get(f"{urls['second']}/api/v1/net/policy")
    assert policy["policy"]["inactive_days"] == 30


def test_independent_verdict_from_raw_evidence(network):
    nodes, urls, ids = network["nodes"], network["urls"], network["ids"]
    everyone = list(nodes.values())
    operators = { "org-primary": [ids["primary"]], "org-second": [ids["second"]],
                  "org-third": [ids["third"], ids["peer"]] }
    app = network["apps"]["app1"]

    def witnessed():
        bundle = get(f"{urls['third']}/api/v1/apps/{app}/evidence")
        if not bundle: return None
        result = evaluate(bundle, ids["net"], operators)
        return (bundle, result) if result["status"] == "witnessed" and result["independence"]["proving"] >= 3 else None

    bundle, result = wait("app1 witnessed by independent operator groups", witnessed, everyone)
    assert result["independence"]["independent_groups"] >= 2
    signers = { signer["node"] for signer in result["signers"] }
    assert ids["peer"] in signers, "the default peer's own signed attestation must reach the network"
    unassigned = evaluate(bundle, ids["net"], None)
    assert unassigned["status"] == "single-witness" and "OPERATORS_UNASSIGNED" not in unassigned["reasons"]
    reasons = { entry["node"]: entry["reason"] for entry in unassigned["independence"]["unresolved"] }
    assert reasons[ids["peer"]] == "OPERATOR_MISSING"
    assert { reasons[node] for node in signers - { ids["peer"] } } == { "OPERATOR_UNREGISTERED" }
    assert unassigned["independence"]["declared_groups"] == 1
    assert evaluate(bundle, "n1.AAAAAAAAAAAAAAAAAAAAAA", operators)["status"] == "invalid"
    same_operator = { "one-org": [ids["primary"], ids["second"], ids["third"], ids["peer"]] }
    assert evaluate(bundle, ids["net"], same_operator)["status"] == "single-witness"

    node = shutil.which("node") or os.environ.get("NODE")
    if node is None:
        import webfluid
        candidate = Path(webfluid.__file__).resolve().parent / "surface" / "dist" / "node" / "node.exe"
        node = str(candidate) if candidate.is_file() else None
    if node:
        sample = network["base"] / "bundle.json"
        sample.write_text(json.dumps({ "bundle": bundle, "anchor": ids["net"], "operators": operators }), encoding="utf-8")
        script = network["base"] / "evaluate.mjs"
        script.write_text(
            'import { readFileSync } from "node:fs"\nimport { pathToFileURL } from "node:url"\n'
            'const { verifier } = await import(pathToFileURL(process.argv[2]).href)\n'
            'const data = JSON.parse(readFileSync(process.argv[3], "utf-8"))\n'
            'const result = await verifier.evaluate(data.bundle, { anchor: data.anchor, operators: data.operators })\n'
            'console.log(JSON.stringify({ status: result.status, groups: result.independence.independent_groups }))\n',
            encoding="utf-8")
        output = subprocess.run([node, "--disable-warning=MODULE_TYPELESS_PACKAGE_JSON", str(script),
                                 str(ADDITIVE / "static" / "js" / "verifier.js"), str(sample)],
                                capture_output=True, text=True, timeout=60)
        assert output.returncode == 0, output.stderr
        web = json.loads(output.stdout.strip().splitlines()[-1])
        assert web == { "status": result["status"], "groups": result["independence"]["independent_groups"] }


def test_same_subject_in_two_apps_stays_separate(network):
    nodes, urls = network["nodes"], network["urls"]
    everyone = list(nodes.values())
    for name in ("app1", "app2"):
        answer = httpx.post(f"{urls[name]}/test/record", json={ "kind": "shop:order", "source": "shop",
                                                                "body": { "order": name }, "subject": "acct:alice",
                                                                "ref": "order-1" }, timeout=10).json()
        assert answer["seq"] >= 1

    def separated():
        result = {}
        for name in ("app1", "app2"):
            app = network["apps"][name]
            entries = (get(f"{urls['second']}/api/v1/apps/{app}/ledger?from=1&limit=500") or {}).get("entries") or []
            orders = [entry["content"]["body"].get("order") for entry in entries if entry["content"]["kind"] == "shop:order"]
            if not orders: return None
            result[name] = orders
        return result

    found = wait("each app's entry replicated under its own app id", separated, everyone)
    assert found == { "app1": ["app1"], "app2": ["app2"] }


def test_chain_receipts_witnessed_and_rechecked_on_another_master(network):
    from wf_peering.protocol import chain, network as protocol
    nodes, urls, ids = network["nodes"], network["urls"], network["ids"]
    everyone = list(nodes.values())
    mint = httpx.post(f"{urls['app1']}/test/event", json={ "ns": "test", "type": "test:mint", "commit": "a" * 64 },
                      timeout=10).json()
    spend = httpx.post(f"{urls['app1']}/test/event", json={ "ns": "test", "type": "test:consume", "commit": "b" * 64,
                                                            "key": "token:e2e" }, timeout=10).json()
    assert mint["status"] == "submitted" and spend["status"] == "submitted"
    again = httpx.post(f"{urls['app1']}/test/event", json={ "ns": "test", "type": "test:consume", "commit": "c" * 64,
                                                            "key": "token:e2e" }, timeout=10).json()
    assert again["status"] == "rejected" and again["reason"] == "ALREADY_CONSUMED"
    identifier = spend["event_id"]
    operators = { "org-primary": [ids["primary"]], "org-second": [ids["second"]], "org-third": [ids["third"]] }

    def witnessed():
        receipt = get(f"{urls['third']}/api/v1/net/receipts/{identifier}")
        if not receipt or receipt.get("status") not in ("included", "witnessed"): return None
        genesis = get(f"{urls['third']}/api/v1/net/genesis")["genesis"]
        objects = []
        cursor = 0
        while True:
            page = get(f"{urls['third']}/api/v1/net/objects?after={cursor}&limit=200")
            objects += [item["object"] for item in page["objects"]]
            if not page["more"]: break
            cursor = page["next"]
        members = [item for item in objects if item["t"] == protocol.MEMBER_CONTEXT]
        result = chain.verify_receipt(receipt, genesis, members, operators=operators, required=2, anchor=ids["net"])
        return (receipt, result) if result["status"] == "witnessed" else None

    receipt, result = wait("receipt witnessed by two independent masters", witnessed, everyone)
    assert result["finality"] == "none" and result["witness_groups"] >= 2
    primary_receipt = get(f"{urls['primary']}/api/v1/net/receipts/{identifier}")
    assert primary_receipt["position"] == receipt["position"]
    assert primary_receipt["block"] == receipt["block"]


def test_primary_outage_does_not_refound_and_recovers_without_duplicates(network):
    nodes, urls, ids = network["nodes"], network["urls"], network["ids"]
    everyone = list(nodes.values())
    before = get(f"{urls['primary']}/api/v1/net/objects?after=0&limit=200")
    nodes["primary"].stop()
    time.sleep(6)
    for name in ("second", "third"):
        status = get(f"{urls[name]}/api/v1/status")
        assert status["network"] == ids["net"]
    pending = httpx.post(f"{urls['app2']}/test/event", json={ "ns": "test", "type": "test:mint", "commit": "d" * 64 },
                         timeout=10).json()
    assert pending["status"] == "submitted"
    nodes["primary"].start()
    genesis = wait("primary back", lambda: get(f"{urls['primary']}/api/v1/net/genesis"), everyone)
    assert genesis["net"] == ids["net"]
    after = wait("primary synced again", lambda: (lambda page: page if page and len(page["objects"]) >= len(before["objects"])
                                                  else None)(get(f"{urls['primary']}/api/v1/net/objects?after=0&limit=200")),
                 everyone)
    oids = [json.dumps(item["object"], sort_keys=True) for item in after["objects"]]
    assert len(oids) == len(set(oids))
    receipt = wait("event submitted during the outage gets included", lambda: (lambda data: data if data and
                   data.get("status") in ("included", "witnessed") else None)(
        get(f"{urls['primary']}/api/v1/net/receipts/{pending['event_id']}")), everyone)
    assert receipt["position"]["height"] >= 1


def test_different_bytes_for_one_path_are_caught_by_observers(network):
    import hashlib
    nodes, urls, ids = network["nodes"], network["urls"], network["ids"]
    everyone = list(nodes.values())
    claimed = hashlib.sha256(b"console.log(1)\n").hexdigest()
    answer = httpx.post(f"{urls['app2']}/test/artifact", json={ "record": {
        "id": "e2e_selective", "additive": "e2e", "type": "script", "hash": claimed, "url": "/test/selective.js",
        "served": True, "version": "v1"
    } }, timeout=10).json()
    assert answer["changed"] is True
    operators = { "org-primary": [ids["primary"]], "org-second": [ids["second"]],
                  "org-third": [ids["third"], ids["peer"]] }
    app = network["apps"]["app2"]

    def mismatch():
        bundle = get(f"{urls['second']}/api/v1/apps/{app}/evidence")
        if not bundle: return None
        result = evaluate(bundle, ids["net"], operators)
        seen = { item["observed"] for item in result["artifacts"] if item["id"] == "e2e_selective" and item["observed"] }
        return result if result["status"] == "mismatch" and len(seen) == 2 else None

    result = wait("observers report different bytes for one path", mismatch, everyone)
    assert "ARTIFACT_SERVED-MISMATCH" in result["reasons"] and result["level"] == "critical"


def test_an_application_changes_its_entry_master_without_a_second_identity(network):
    nodes, urls, ids = network["nodes"], network["urls"], network["ids"]
    everyone = list(nodes.values())
    app = nodes["app2"]
    before = get(f"{urls['app2']}/peering/api/v1/net/status")
    app.stop()
    config = app.root / "fluid" / "config.py"
    config.write_text(config.read_text(encoding="utf-8").replace(repr(urls["third"]), repr(urls["primary"])),
                      encoding="utf-8")
    app.start()
    status = wait("application re-joined through the primary", lambda: (lambda data: data if data and data.get("entry")
                  and data["entry"].get("node") == ids["primary"] and data.get("link", {}).get("state") == "active"
                  else None)(get(f"{urls['app2']}/peering/api/v1/net/status")), everyone)
    assert status["app"] == before["app"] and status["net"] == before["net"] == ids["net"]
    listing = get(f"{urls['primary']}/api/v1/apps")
    assert listing["total"] == 2 and before["app"] in [item["app"] for item in listing["items"]]


def test_unreachable_upstream_never_founds(network):
    base = network["base"]
    port = free_port()
    orphan = peer_node(base, "orphan", port, { "IS_MASTER": True, "JOIN_MASTER": f"http://127.0.0.1:{free_port()}",
                                               "PEERING_PUBLIC_URL": f"http://127.0.0.1:{port}",
                                               "LEGAL": legal("Orphan Beispiel") })
    orphan.start()
    try:
        status = wait("orphan reports retrying", lambda: (lambda data: data if data and data.get("link")
                      and data["link"].get("state") in ("retrying", "joining") else None)(
            get(f"http://127.0.0.1:{port}/api/v1/status")), [orphan], 60)
        time.sleep(8)
        status = get(f"http://127.0.0.1:{port}/api/v1/status")
        assert status["network"] is None and status["topology"] == "secondary"
        assert not (orphan.root / "keys" / "genesis.json").exists()
    finally:
        orphan.stop()
