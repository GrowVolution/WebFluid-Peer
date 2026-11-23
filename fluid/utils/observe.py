from wf_peering.exceptions import CheckError
from wf_peering.protocol import integrity as spec
from wf_peering.settings import settings
from wf_peering.utils import netcheck
from urllib.parse import urlsplit
import hashlib, json, re

MAX_ARTIFACTS = 32
PINNED = re.compile(r"/(?:[0-9a-f]{40}|[0-9a-f]{64})/.")


def _digest(algorithm: str, data: bytes) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def parse_manifest(data: bytes, artifact: str | None = None) -> dict | None:
    try: manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError): return None
    if not isinstance(manifest, dict): return None
    algorithm = manifest.get("algorithm") or "sha256"
    if not isinstance(algorithm, str) or algorithm not in spec.ALGORITHMS: return None
    if manifest.get("format") == 2:
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict): return None
        entry = artifacts.get(artifact)
        if entry is None: return { "unlisted": True }
        name = artifact
    else:
        entry, name = manifest, manifest.get("artifact")
    if not isinstance(entry, dict) or not isinstance(entry.get("versions"), list): return None
    versions, served = {}, {}
    for item in entry["versions"]:
        if not isinstance(item, dict): continue
        version, value = item.get("version"), item.get(algorithm) or item.get("hash")
        if not isinstance(version, str) or not version or not isinstance(value, str) \
                or len(value) != spec.ALGORITHMS[algorithm] or any(c not in "0123456789abcdefABCDEF" for c in value):
            return None
        if version in versions: return None
        versions[version] = value.lower()
        http = item.get("http")
        if isinstance(http, dict) and isinstance(http.get(algorithm), str) \
                and len(http[algorithm]) == spec.ALGORITHMS[algorithm]:
            served[version] = http[algorithm].lower()
    latest = entry.get("latest")
    if not isinstance(latest, str) or latest not in versions: return None
    return { "algorithm": algorithm, "versions": versions, "served": served, "latest": latest, "artifact": name }


async def trusted_reference(record: dict) -> dict:
    artifact = record["id"]
    url, origin = settings.references.get(artifact), "peer-config"
    if not url:
        url, origin = (record.get("reference") or {}).get("manifest"), "host-supplied"
    if not url: return { "status": "unavailable", "reason": "NO_REFERENCE" }
    if origin == "peer-config" and not settings.debug and not PINNED.search(urlsplit(url).path):
        return { "status": "unavailable", "reason": "REFERENCE_NOT_PINNED", "url": url, "origin": origin }
    try: manifest = parse_manifest(await netcheck.reference(url), artifact)
    except CheckError as exc:
        return { "status": "unavailable", "reason": exc.code, "url": url, "origin": origin }
    if manifest is None: return { "status": "unavailable", "reason": "INVALID_MANIFEST", "url": url, "origin": origin }
    if manifest.get("unlisted"):
        return { "status": "unavailable", "reason": "NOT_IN_REFERENCE", "url": url, "origin": origin }
    if manifest.get("artifact") not in (None, artifact):
        return { "status": "unavailable", "reason": "ARTIFACT_MISMATCH", "url": url, "origin": origin }
    return dict(manifest, status="ok", url=url, origin=origin)


async def observe(origin: str, record: dict) -> dict:
    artifact, algorithm = record["id"], record["algorithm"]
    result = { "artifact": artifact, "claimed": record["hash"], "algorithm": algorithm, "url": record.get("url") }
    if record.get("url"):
        try:
            response = await netcheck.get(origin, record["url"], settings.max_response_bytes)
            if response["status"] == 200:
                result["observed"] = _digest(algorithm, response["body"])
                result["size"] = len(response["body"])
            else: result["fetch_error"] = f"HTTP_{response['status']}"
        except CheckError as exc: result["fetch_error"] = exc.code
    else: result["fetch_error"] = "NOT_PUBLICLY_SERVED"

    reference = await trusted_reference(record)
    result["reference"] = { key: reference.get(key) for key in ("status", "reason", "url", "origin", "latest") }
    observed = result.get("observed")
    if reference.get("status") == "ok":
        same = reference["algorithm"] == algorithm
        versions = reference["versions"] if same else {}
        served = reference.get("served") or {} if same else {}
        value = observed or record["hash"]
        matched = next((version for version, digest in served.items() if digest == value), None) \
            or next((version for version, digest in versions.items() if digest == value and version not in served),
                    None)
        result["served_version"] = matched
        result["latest_version"] = reference.get("latest")
        result["reference_hash"] = (served.get(matched) or versions.get(matched)) if matched else None

    if observed is None: status = "unreachable" if result.get("fetch_error") != "NOT_PUBLICLY_SERVED" else "not-served"
    elif observed != record["hash"]: status = "served-mismatch"
    elif reference.get("status") != "ok" or reference.get("origin") != "peer-config": status = "unreferenced"
    elif result.get("served_version") is None: status = "reference-mismatch"
    elif result.get("latest_version") and result["served_version"] != result["latest_version"]: status = "outdated"
    else: status = "verified"
    result["status"] = status
    return result
