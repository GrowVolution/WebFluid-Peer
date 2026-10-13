from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select
import hashlib, json

from wf_peering.models.integrity import Observation
from wf_peering.protocol import integrity as spec
from wf_peering.protocol.entries import utc_now
from wf_peering.services.store import dumps, Conflicts
from wf_peering.settings import settings
from wf_peering.utils import netcheck


def _digest(algorithm: str, data: bytes) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def parse_manifest(data: bytes, artifact: str | None = None) -> dict | None:
    try: manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError): return None
    if not isinstance(manifest, dict): return None
    algorithm = manifest.get("algorithm") or "sha256"
    if algorithm not in spec.ALGORITHMS: return None
    if manifest.get("format") == 2:
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict): return None
        entry = artifacts.get(artifact)
        if entry is None: return { "unlisted": True }
        name = artifact
    else:
        entry, name = manifest, manifest.get("artifact")
    if not isinstance(entry, dict) or not isinstance(entry.get("versions"), list): return None
    versions = {}
    for item in entry["versions"]:
        if not isinstance(item, dict): continue
        version, value = item.get("version"), item.get(algorithm) or item.get("hash")
        if isinstance(version, str) and isinstance(value, str) and len(value) == spec.ALGORITHMS[algorithm]:
            versions[version] = value.lower()
    latest = entry.get("latest") if entry.get("latest") in versions else None
    return { "algorithm": algorithm, "versions": versions, "latest": latest, "artifact": name }


async def trusted_reference(record: dict) -> dict:
    artifact = record["id"]
    url, origin = settings.references.get(artifact), "peer-config"
    if not url:
        url, origin = (record.get("reference") or {}).get("manifest"), "host-supplied"
    if not url: return { "status": "unavailable", "reason": "NO_REFERENCE" }
    try: manifest = parse_manifest(await netcheck.reference(url), artifact)
    except netcheck.CheckError as exc:
        return { "status": "unavailable", "reason": exc.code, "url": url, "origin": origin }
    if manifest is None: return { "status": "unavailable", "reason": "INVALID_MANIFEST", "url": url, "origin": origin }
    if manifest.get("unlisted"):
        return { "status": "unavailable", "reason": "NOT_IN_REFERENCE", "url": url, "origin": origin }
    if manifest.get("artifact") not in (None, artifact):
        return { "status": "unavailable", "reason": "ARTIFACT_MISMATCH", "url": url, "origin": origin }
    return dict(manifest, status="ok", url=url, origin=origin)


async def observe(record: dict) -> dict:
    artifact, algorithm = record["id"], record["algorithm"]
    result = { "artifact": artifact, "claimed": record["hash"], "algorithm": algorithm, "url": record.get("url") }

    if record.get("url"):
        try:
            response = await netcheck.get(settings.host, record["url"], settings.max_response_bytes)
            if response["status"] == 200:
                result["observed"] = _digest(algorithm, response["body"])
                result["size"] = len(response["body"])
            else:
                result["fetch_error"] = f"HTTP_{response['status']}"
        except netcheck.CheckError as exc:
            result["fetch_error"] = exc.code
    else:
        result["fetch_error"] = "NOT_PUBLICLY_SERVED"

    reference = await trusted_reference(record)
    result["reference"] = { key: reference.get(key) for key in ("status", "reason", "url", "origin", "latest") }
    observed = result.get("observed")
    if reference.get("status") == "ok":
        versions = reference["versions"] if reference["algorithm"] == algorithm else {}
        matched = next((version for version, value in versions.items() if value == (observed or record["hash"])), None)
        result["served_version"] = matched
        result["latest_version"] = reference.get("latest")
        result["reference_hash"] = versions.get(matched) if matched else versions.get(record.get("served_version") or "")

    if observed is None: status = "unreachable" if result.get("fetch_error") != "NOT_PUBLICLY_SERVED" else "not-served"
    elif observed != record["hash"]: status = "served-mismatch"
    elif reference.get("status") != "ok": status = "unreferenced"
    elif result.get("served_version") is None: status = "reference-mismatch"
    elif result.get("latest_version") and result["served_version"] != result["latest_version"]: status = "outdated"
    else: status = "verified"
    result["status"] = status
    return result


async def run() -> list[dict]:
    if not settings.is_peer: return []
    from wf_peering.services.integrity import Integrity
    results = []
    for group in await Integrity.current():
        for item in group["records"]:
            record = item["record"]
            if item.get("missing_since") or record.get("served") is False: continue
            try: outcome = await observe(record)
            except Exception as exc:
                log_factory.exception(exc, f"[peering] Observing {record.get('id')} failed.")
                continue
            results.append(outcome)
            async with db.async_executor(model=Observation) as e:
                await e.insert(Observation(
                    artifact=record["id"], ts=utc_now(), status=outcome["status"],
                    claimed_hash=outcome.get("claimed"), observed_hash=outcome.get("observed"),
                    reference_hash=outcome.get("reference_hash"), served_version=outcome.get("served_version"),
                    latest_version=outcome.get("latest_version"), detail=dumps(outcome)
                ))
            await _escalate(outcome)
    return results


async def _escalate(outcome: dict):
    status = outcome["status"]
    artifact = outcome["artifact"]
    if status == "served-mismatch":
        await Conflicts.record("artifact-served-mismatch", "critical",
                               f"The host serves {artifact} with a hash that differs from its own integrity claim.",
                               outcome, subject=f"artifact:{artifact}",
                               key={ "claimed": outcome.get("claimed"), "observed": outcome.get("observed") })
    elif status == "reference-mismatch":
        await Conflicts.record("artifact-reference-mismatch", "critical",
                               f"{artifact} does not match any version of its trusted reference.",
                               outcome, subject=f"artifact:{artifact}",
                               key={ "observed": outcome.get("observed") or outcome.get("claimed") })
    elif status == "outdated":
        await Conflicts.record("artifact-outdated", "high",
                               f"The host serves {artifact} {outcome.get('served_version')} while "
                               f"{outcome.get('latest_version')} is the latest published version.",
                               outcome, subject=f"artifact:{artifact}",
                               key={ "served": outcome.get("served_version"), "latest": outcome.get("latest_version") })


async def latest(artifact: str) -> dict | None:
    async with db.async_executor(model=Observation) as e:
        result = await e.exec(select(Observation).where(Observation.artifact == artifact)
                              .order_by(Observation.id.desc()).limit(1))
        row = result.first()
        if not row: return None
        return json.loads(row.detail) | { "ts": row.ts }
