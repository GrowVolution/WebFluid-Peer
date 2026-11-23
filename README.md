# peering

> A WebFluid app — a master or a peer of a WebFluid peering network.

A peering network checks WebFluid applications from the outside so that nobody has to trust an
application's operator — the network does not even trust its own operators. This app is the node that
forms and serves the network:

| Started as           | Configuration                                         | Does                                                                                                   |
|----------------------|-------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Primary master**   | `IS_MASTER = True`, `JOIN_MASTER = None`              | Founds the network (genesis, network id), sets its policy, sequences the event chain, admits members, serves the dashboard, the API and its legal pages. |
| **Secondary master** | `IS_MASTER = True`, `JOIN_MASTER = "<master URL>"`    | Joins an existing network through any master, verifies and replicates everything itself, admits members, witnesses blocks, serves its own dashboard and legal pages. |
| **Default peer**     | `IS_MASTER = False` (default), `JOIN_MASTER = "<URL>"` | Joins through exactly one master and only makes outbound connections: replicates applications itself and sends signed observations through its master. No public URL, no UI, no join endpoint. |

Applications take part with the `peering` Additive (`PEERING_MASTER_URL`). Everything the roles must
do identically — protocols, verification, the verdict, the client — comes from the `wf-peering`
extension; its `PROTOCOL.md` is the normative wire protocol.

| This app (`fluid/`)    | Job                                                                                                 |
|------------------------|-----------------------------------------------------------------------------------------------------|
| `utils/topology.py`    | Resolves `IS_MASTER`/`JOIN_MASTER` into primary, secondary or peer — and fails clearly on bad values. |
| `utils/network.py`     | Founding and restoring the genesis, the primary's policy, challenges, join admission, request authentication. |
| `utils/store.py`       | The store of signed network objects: verification and authorization on receipt, paging for sync.  |
| `utils/link.py`        | Join with backoff, paged sync from masters, submitting a peer's attestations.                      |
| `utils/apps.py`        | Application registry, sightings, replication from the application's origin, attestations, evidence bundles, search, retention. |
| `utils/chain.py`       | The event chain: submissions, blocks (primary), witnesses (secondaries), receipts.                 |
| `utils/legacy.py`      | Import of a former peer database's verified host ledger and the legacy export.                     |
| `utils/legal.py`       | The data-flow matrix behind the privacy policy and the role-dependent check of the operator data.  |
| `api/`, `app/`         | `/api/health`, `/api/v1/status` on every node; the network API, dashboard, `/imprint` and `/privacy` on masters only. |

---

## Why

Trust in an application should not depend on its operator. A network of independently operated
masters and peers checks what every application publishes — its signed history, the files it serves,
the key changes of its users — and every client recomputes the verdict from the signed raw evidence
with an assignment of signers to operators it chooses itself.

## For developers and agents

- [.agents/SKILL.md](.agents/SKILL.md) — what a coding agent needs to work on this app
- The `wf-peering` extension: `PROTOCOL.md` (wire protocol), `CONTRACT.md` (settings, building blocks)

---

## Minimal configurations

All values are Python class attributes in `fluid/_my_config.py` (gitignored); `None` means Python `None`.
These keys are not read from `.ini` files. `JOIN_MASTER` defaults to `"https://peers.webfluid.dev"`, so
`IS_MASTER = True` alone makes a secondary of that network and only an explicit `JOIN_MASTER = None`
founds a network. A default peer with `JOIN_MASTER = None`, `""` or an invalid origin refuses to start
with a message naming the key.

**Primary master**

```python
class MyConfig:
    IS_MASTER = True
    JOIN_MASTER = None
    PEERING_PUBLIC_URL = "https://peers.example.org"
    NETWORK_NAME = "example"
    LEGAL = { ... }                      # see "Operator information" below
```

After the first start the log names the network id; set `PEERING_NETWORK_ANCHOR = "n1.…"` then, so a
lost database can never found a new network silently.

**Secondary master**

```python
class MyConfig:
    IS_MASTER = True
    JOIN_MASTER = "https://peers.example.org"      # any master of the network
    PEERING_PUBLIC_URL = "https://peers2.example.net"
    PEERING_NETWORK_ANCHOR = "n1.…"                # optional: refuse any other network
    LEGAL = { ... }
```

**Default peer** (with `app_configs/peer.example.ini`: `WF_PROCESSING = 0`)

```python
class MyConfig:
    JOIN_MASTER = "https://peers2.example.net"
```

**Application** (WebFluid app with the `peering` Additive)

```python
class Config:
    PEERING_MASTER_URL = "https://peers2.example.net"
```

The policy of the network — inactivity period (`PEERING_INACTIVE_DAYS`, default 30), maximal age of
attestations and the number of independent operator groups for *witnessed* — is set only on the
primary and replicated as signed objects; the same keys on a secondary have no effect.
`PEERING_OPERATORS` (`{group: [node ids or keys]}`) is the operator assignment this master uses for
the verdicts it displays; it is labelled as this operator's view.

`PEERING_TRUSTED_REFERENCES` (`{artifact id: manifest URL}`) names the reference manifests this node
trusts; only these make an observation `verified`, a manifest the application names itself stays
`unreferenced`. Each URL must address a full commit id (40 or 64 hex characters as a path segment),
for example the peering verifier of a published release:

```python
class Config:
    PEERING_TRUSTED_REFERENCES = {
        "peering_verifier": "https://raw.githubusercontent.com/GrowVolution/WF_peering/<commit>/integrity/manifest.json"
    }
```

A branch or tag can move, so outside debug mode such a URL is not fetched and the observation
reports `REFERENCE_NOT_PINNED` (`unreferenced`); debug mode accepts it for development. Allowed hosts
are `PEERING_REFERENCE_HOSTS` (default `raw.githubusercontent.com`).

---

## Running a node

Requirements: WebFluid `1.0.0rc1` and the `wf-peering` extension from its checkout:

```bash
pip install -e ../wf-site/extensions/peering
wf migrate init main && wf migrate revision main -a && wf migrate upgrade main
wf run main -p 8001
```

Masters use `app_configs/master.example.ini`, default peers `app_configs/peer.example.ini`. The node
key is created in `keys/node.key` (mode `0600`); a primary also writes `keys/genesis.json` next to it.
Keep both in your backups: a primary that loses its database restores the binding from
`genesis.json`; one that loses its key cannot sign as primary again — the network stays with the old
id and the secondaries keep it.

**Master outage.** Secondaries keep the network, admit members and accept events, which stay
*submitted* until the primary is back and orders them. A secondary never founds a network; an
unreachable upstream is retried.

**Changing the entry master** inside the same network keeps identity and history. Another network
needs an explicit rebinding (`PEERING_NETWORK_ANCHOR` set to the new id).

### With Docker

`docker-compose.yaml` holds two example services: `master` behind Traefik with a public router, and
`peer` without any Traefik label, published port or public URL. The `Dockerfile` installs `wf-peering`
from PyPI; until the extension version in this working tree is released, install it from the checkout
instead (mount it and `pip install -e`).

### Local multi-node demo

The integration test starts a complete network in separate processes with their own keys and
databases — a primary, a secondary, a secondary that joins through the secondary, a default peer on an
unknown port and two applications with the real `peering` Additive:

```bash
cd tests
PEERING_E2E=1 python -m pytest -q integration/test_network_e2e.py
```

`PEERING_E2E_KEEP=1` keeps the folders (logs in `node.log`) under the temp directory. The test checks
formation and convergence, the inventory of a default peer (`/api/health`, `/api/v1/status` only), a
verdict recomputed from raw evidence in Python and in the browser verifier, the separation of two
applications, a receipt witnessed by two masters, a primary outage without re-founding and an
unreachable upstream that never founds.

---

## Checking an application yourself

1. Obtain a master URL and the network id from a source you trust, not from the application.
2. Fetch `GET <master>/api/v1/apps/<app id>/evidence`. It contains only signed objects: genesis,
   policies, admissions, the application's heads, attestations, sightings and consistency proofs.
3. Evaluate it with your anchor and your operator assignment — in Python
   `wf_peering.protocol.evidence.evaluate(bundle, anchor, operators)`, in a native client the users SDK's
   `NetworkEvidence.verifyApp`, in a browser outside the application `verifier.evaluate`. All three
   reproduce the shared vectors of `wf-peering`.

The master's dashboard (`/`, `/apps/<id>`) shows the same verdict computed by that master with its
operator's assignment, plus the raw evidence link.

---

## Operator information

Masters render `/imprint`, `/privacy` and the machine-readable operator statement
`GET /api/v1/net/operator` from `LEGAL`; default peers serve none of them. Without complete information
a master refuses to start outside debug mode (`LEGAL: incomplete …` names every missing field); in
debug mode the pages show what is missing. Conditional fields are only required when their condition
applies (the validation names them).

```python
LEGAL = {                                                  # example values — replace every one
    "operator": {
        "name": "Beispiel Peering e.V.", "form": "association",   # natural_person, sole_trader, company, association, public_body
        "country": "DE",                                   # ISO 3166-1 alpha-2 of the establishment
        "commercial": False,                               # True: geschäftsmäßig, in der Regel gegen Entgelt → § 5 DDG
        "registered": True,                                # companies always; then "register" is required
        "register": { "court": "Amtsgericht Musterstadt", "type": "VR", "number": "VR 12345" },
        "representatives": ["Erika Beispiel (Vorsitz)"],   # required for company, association, public_body
        "address": ["Musterweg 1", "12345 Musterstadt", "Deutschland"],
        "email": "kontakt@example.org", "contact_form": "https://example.org/kontakt",
        # optional: "legal_form" (required for companies), "phone", "vat_id", "economic_id", "capital",
        # "outstanding", "permit_required" + "supervisory_authority", "profession", "in_liquidation",
        # "journalistic" + "editorial" {"name", "address"} (§ 18 Abs. 2 MStV)
    },
    "privacy": {
        "legal_basis": "art6_1_f",                         # the operator confirms the documented assessment
        "controller_email": "datenschutz@example.org",
        "hosting": "Example Hosting GmbH, data centre in Germany, processing on our behalf (Art. 28 GDPR)",
        "proxy_logs_days": 7, "backups_days": 14,          # 0 / None when not kept
        "supervisory_authority": "…",
        "transfers": False,                                # False = the operator transfers nothing itself; or a text with the safeguards
        "dpo": False,                                      # False = none appointed; or {"name", "email"}
        # outside the EU/EEA: "representative": {"name", "address"} or "representative_exempt": True (Art. 27(2) GDPR)
        # optional: "controller": {...}, "joint": "...", "updated": "..."
    }
}
```

The imprint names the provisions it follows (`§ 5 DDG` only for `commercial` operators, `§ 18 Abs. 1
MStV` always, `§ 18 Abs. 2 MStV` with an editorial). `/api/v1/net/operator` returns the public imprint
fields (`fields.imprint`: name, form, legal form, address, country, contact data, representatives,
register, VAT/economic id, capital, supervisory authority, profession, liquidation, editorial,
provisions — never the `privacy` section or deployment values), their SHA-256 and the master's signed
operator declaration. Only the declaration is replicated to the network: name, form, country and the
register entry, VAT and economic identification number (`fields.replicated`), plus the imprint digest.
Clients use it to count distinguishable operators without a manual list; a master that copies another
organisation's register number only merges into that organisation's group. Publish every identifier
you have — a master that names only its VAT number and one that names only the register entry of the
same company count as two operators.

The operator must confirm the facts the texts rest on: who runs the node and in which legal form,
whether `§ 5 DDG` applies (geschäftsmäßige digitale Dienste) or only `§ 18 MStV`, the hosting set-up
and whether the reverse proxy logs, backup periods, the competent supervisory authority, known
third-country transfers and whether arrangements with other operators exist. The privacy policy
follows the data-flow matrix in `fluid/utils/legal.py`; the site sets no cookies and uses no local
storage.

---

## Former peer databases

A peer of the former host–peer topology kept a verified copy of one host's ledger. At startup the app
imports it once, after verifying every entry against the pinned host key, as the replica of the
application `app1.<hash of that key>` (`peering_state` → `legacy_migration`). A failed verification
imports nothing; the legacy tables stay untouched. `LegacyMigration.export(path)` writes the rest
(sync runs, observations, legacy checkpoints, conflicts) as readable JSON.

---

## Tests

```bash
cd tests
python -m pytest -q
```

In-process tests of a primary (topology resolution, founding, join rules, replay and audience checks,
inactivity at the exact boundary, policy, chain, evidence, search, dashboard and legal pages, legacy
import). The multi-process test runs with `PEERING_E2E=1` (see above).

---

## License

The WebFluid Peer application is maintained by **GrowVolution e.V.** and released under the
[GNU General Public License v3.0](LICENSE).
