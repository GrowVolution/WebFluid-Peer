---
name: app-webfluid-peer
description: Work on the WebFluid-Peer app (`peering` repository), an independent peer that replicates and verifies a WebFluid host — live ledger replication, the daily full sync, observations of served artifacts, checkpoints and the public peer API. Load it before changing how a peer syncs, observes, checkpoints or reports trust, and before deploying or configuring a peer.
---

# WebFluid-Peer — agent guide

<!-- index -->
This file is short enough to read whole; the ranges are for coming back to one section. Every file
it points to opens with an index of the same shape — read those first 30 lines, then only the ranges
the task needs.

- `23-38` **Rules**
- `39-47` **Verify**
- `48-51` **References**
<!-- /index -->

The peer is a plain WebFluid main app without Additives. Everything it shares with the host —
protocols, storage, verification, checkpoints, trust — comes from the `wf-peering` extension; this
repository adds only what only a peer does: the connection to the host, the full sync, the
observations and the peer role.

## Rules

1. **Peer-only behaviour lives in `fluid/`; shared behaviour belongs in `wf-peering`.** If host and
   peer must agree on it, it is extension code and is changed there; every contract change in the
   extension's `CHANGELOG.md` is adopted here in the same release.
2. **`PeerRole` is the only seam.** Add a method to the role in `fluid/utils/role.py` instead of
   branching on the role inside shared code.
3. **Never trust the host's word.** Only peer-configured reference manifests establish verified provenance.
   Host-supplied manifests remain unreferenced. Shared head verification binds origin and freshness;
   range pages must advance. Observations fetch what the host serves and compare it with
   the published references; a mismatch is recorded, never smoothed over.
4. **One origin.** `PEERING_HOST` is the host's `BASE_URL` exactly; a second spelling breaks
   identity checks.
5. **The factory lives in `fluid/__init__.py`** (WebFluid `1.0.0rc1`); `main.py` only starts it.
6. **The node key is a file** (`PEERING_KEY_FILE`); never commit it or put it into config.

## Verify

- `python -m pytest -q -p no:cacheprovider` in `tests/` boots the peer in-process.
- `GET /api/v1/status` of a running peer shows the role `peer`, the host it watches, the ledger
  head and the latest checkpoint.
- Against a local host: run the host with the `peering` Additive, then `wf run main` here with
  `PEERING_HOST` (in `fluid/config.py`, overridable in `fluid/_my_config.py`) set to the host's
  `BASE_URL`.

## References

- `../README.md` — running a peer, what it publishes, tests
- The `wf-peering` extension's `CONTRACT.md` — settings, protocols, public API, trust score
