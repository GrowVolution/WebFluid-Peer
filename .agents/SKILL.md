---
name: app-webfluid-peer
description: Work on the WebFluid peering node app (`peering` repository) — primary and secondary masters and outbound-only default peers of a peering network: genesis, join, signed-object sync, application replication and attestations, the event chain, the dashboard and the legal pages. Load it before changing how a node joins, syncs, attests, sequences or reports, and before deploying or configuring one.
---

# WebFluid-Peer — agent guide

<!-- index -->
This file is short enough to read whole; the ranges are for coming back to one section. Every file
it points to opens with an index of the same shape — read those first 30 lines, then only the ranges
the task needs.

- `24-41` **Rules**
- `42-49` **Verify**
- `50-53` **References**
<!-- /index -->

The node is a plain WebFluid main app without Additives. Everything it shares with applications and
other nodes — protocols, verification, the verdict, the client — comes from the `wf-peering`
extension; this repository adds what only masters and peers do: topology, genesis, join admission,
the signed-object store and sync, replication and attestation, the event chain, the dashboard and the
legal pages.

## Rules

1. **Peer-only behaviour lives in `fluid/`; shared behaviour belongs in `wf-peering`.** If host and
   peer must agree on it, it is extension code and is changed there; every contract change in the
   extension's `CHANGELOG.md` is adopted here in the same release.
2. **The topology decides the surface.** `utils/topology.resolve` turns `IS_MASTER`/`JOIN_MASTER` into
   primary, secondary or peer; master routers, assets, templates and translations are registered only
   for masters (`fluid/app/`), a default peer serves `/api/health` and `/api/v1/status` and nothing else.
3. **Never trust a relay.** Every received object is verified and authorized by `ObjectStore.put`
   (signature, network, signer role, membership chain); masters transport but never author others'
   statements. Only node-configured reference manifests establish provenance, outside debug mode only
   at a full commit id.
4. **Never found by accident.** Only `JOIN_MASTER = None` founds; an existing binding or
   `keys/genesis.json` is restored instead, an anchor without genesis refuses to start, an unreachable
   upstream is retried.
5. **The factory lives in `fluid/__init__.py`** (WebFluid `1.0.0rc1`); `main.py` only starts it.
6. **The node key is a file** (`PEERING_KEY_FILE`); never commit it or put it into config.

## Verify

- `python -m pytest -q -p no:cacheprovider` in `tests/` boots the peer in-process.
- `PEERING_E2E=1 python -m pytest -q integration/test_network_e2e.py` in `tests/` runs a real
  multi-process network (masters, peer, two applications with the Additive).
- `GET /api/v1/status` of a node shows its topology, network id, anchor, policy, members and sync
  sources.

## References

- `../README.md` — running a peer, what it publishes, tests
- The `wf-peering` extension's `CONTRACT.md` — settings, protocols, public API, trust score
