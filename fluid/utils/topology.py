from wf_peering.exceptions import PolicyError
from wf_peering.protocol.netpolicy import parse_target
from dataclasses import dataclass

from ..exceptions import ConfigurationError

UNSET = object()
TRUE = (True, 1, "1", "true", "True")


def _origin(key: str, value, insecure: bool) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ConfigurationError(key, "MISSING", "a master URL is required, e.g. \"https://peers.webfluid.dev\"")
    if not isinstance(value, str):
        raise ConfigurationError(key, "INVALID_URL", f"expected a URL string, got {type(value).__name__}")
    try: target = parse_target(value.strip().rstrip("/"), insecure, (443, 80) if insecure else (443,))
    except PolicyError as exc:
        raise ConfigurationError(key, str(exc), f"{value!r} is not an allowed master origin") from exc
    return target.origin


def resolve(config, debug: bool = False) -> Topology:
    insecure = config.get("PEERING_ALLOW_INSECURE") in TRUE or debug
    master = config.get("IS_MASTER") in TRUE
    join = config.get("JOIN_MASTER", UNSET)
    if join is UNSET:
        from fluid.config import DEFAULT_MASTER
        join = DEFAULT_MASTER
    public = config.get("PEERING_PUBLIC_URL") or config.get("BASE_URL")
    own = None
    if master:
        own = _origin("PEERING_PUBLIC_URL", public, insecure)
        if join is None: return Topology("master", True, None, own)
    upstream = _origin("JOIN_MASTER", join, insecure)
    if own is not None and upstream == own:
        raise ConfigurationError("JOIN_MASTER", "SELF_JOIN", "a master cannot join itself; use None to found a network")
    return Topology("master" if master else "peer", False, upstream, own)


@dataclass(frozen=True)
class Topology:
    role: str
    primary: bool
    upstream: str | None
    public: str | None

    @property
    def label(self) -> str:
        if self.role == "peer": return "peer"
        return "primary" if self.primary else "secondary"
