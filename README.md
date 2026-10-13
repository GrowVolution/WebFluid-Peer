# peering

> A WebFluid app — an independent peer of a WebFluid host.

A peer watches one host from the outside. It replicates the host's signed ledger, checks every entry,
key change and signed user action itself, fetches the scripts the host actually serves and compares them
with the published references, signs a daily checkpoint and assesses how far the host can be trusted.
Its results are public, so users, other peers and the users SDK can compare them.

This is a plain WebFluid main app. It runs **without Additives** (`WF_ADDITIVES` stays off) and is the
complement of the `peering` Additive, which only runs on the host. Both use the `wf-peering` extension for
everything they must do identically: protocols, storage, verification, checkpoints and the trust score.

| This app (`fluid/`)                | Job                                                                                    |
|------------------------------------|----------------------------------------------------------------------------------------|
| `utils/sync.py`                    | `HostLink`: the WebSocket to `/peering/ws/peer` with live replication; `FullSync`: the daily full sync over the host API with root comparison. |
| `utils/observe.py`                 | Fetches every published artifact from the host and checks it against the host's claim and the trusted reference. |
| `utils/role.py`                    | `PeerRole`: checkpoint basis, checkpoint publication, peer-only trust signals, status. |
| `jobs.py`                          | Observation interval and the daily full sync (23:59 UTC by default).                   |
| `api/`                             | The public API under `/api/v1` (shared handlers from `wf-peering`, plus `/sync` and `/integrity/observations`). |
| `app/`                             | The status page at `/`.                                                                |

---

## Running a peer

Requirements: WebFluid `1.0.0b3` or newer and the `wf-peering` extension in the same environment:

```bash
pip install -e ../wf-site/extensions/peering     # or: wf ocean install -e peering
```

`app_configs/main.ini` (`main.example.ini` is the template):

```ini
[general]
SECRET_KEY = <random>

[extensions]
EXT_SQLALCHEMY = 1
EXT_SCHEDULING = 1
EXT_BABEL = 1

[features]
WF_PROCESSING = 1

[data]
DATABASE_URI = sqlite:///main.db
```

`fluid/_my_config.py` (gitignored) overrides the defaults in `fluid/config.py`:

```python
class MyConfig:
    PEERING_HOST = "https://app.example.org"        # the host this peer watches
    PEERING_PUBLIC_URL = "https://peer.example.net" # where this peer is reachable
    # PEERING_HOST_KEY = "…"                        # pin the host key instead of trusting the first one
    # PEERING_TRUSTED_REFERENCES = { "users_e2ee": "https://raw.githubusercontent.com/…/manifest.json" }
```

`fluid/config.py` already trusts the published references of `users_e2ee` and `users_session` (users
integrity repository) and of `ocean_integrity` (ocean integrity repository); both repositories publish a
format 2 manifest that lists several artifacts. The status page is translated on the server, so the app
needs `EXT_BABEL`; `fluid/config.py` offers English and German.

```bash
wf migrate init main && wf migrate revision main && wf migrate upgrade main
wf run main -p 8001
```

### With Docker

The `Dockerfile` extends the WebFluid image with `wf-peering`; `docker-compose.yaml` is an example stack
for a Swarm behind Traefik that mounts the checkout as `/app` and starts the app `main` on port 8000. Set
the router rule to the peer's own domain — the one in `PEERING_PUBLIC_URL`.

For local development, run the host and the peer with `-d`: in debug mode `wf-peering` allows `http` and
local addresses (the defaults in `fluid/config.py` point at `http://localhost:8000` and `:8001`) and leaves
HTTPS out of the trust assessment, so nothing fails with `HTTPS_REQUIRED`. The signed reports and the status
page say that the node runs in debug mode.

`PEERING_HOST` must be exactly the origin the host signs (its `PEERING_PUBLIC_URL`, by default its
`BASE_URL`) and the address browsers and apps use for it. A different spelling of the same server — a LAN
address instead of `localhost` — makes the peer report the host's identity as `URL_MISMATCH`, and clients
don't count the peer as confirming the host they visit.

The node key is created in `keys/node.key` (gitignored, mode `0600`) on first start, or taken from
`PEERING_NODE_KEY`. Losing it gives the peer a new identity; other nodes record that as a key change.

A peer is only as independent as its infrastructure: run it on a different provider, network and domain
than the host, and do not reuse the host's TLS certificate. The trust assessment detects shared /24 or /48
networks, registrable domains and certificate keys and counts such observers as one.

---

## What it publishes

`GET /api/v1/…` — the same read-only API as the host (see the `wf-peering` README), answered from the peer's
own verified copy: `/node`, `/status`, `/ledger…`, `/accounts/{handle}`, `/integrity`, `/hash?id=` (with the
peer's own `observation`), `/checkpoints…`, `/peers`, `/trust`, `/conflicts`, plus:

- `GET /api/v1/sync` — next full sync and checkpoint, recent sync runs, state of the host link.
- `GET /api/v1/integrity/observations` — what the peer actually downloaded from the host.

The status page at `/` reads only this API.

---

## Tests

```bash
pytest tests
```

The tests run a copy of this app against a fake host (`tests/fakehost.py`) and the installed `wf-peering`:
full and live sync, retries, schema mismatches, rewritten and truncated histories, a changed host key,
artifact observations against format 1 and format 2 references, unserved records, node identity and TLS
classification, trust and the path layout.

---

## License

[GNU General Public License v3.0](LICENSE)
