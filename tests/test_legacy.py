import json


async def test_legacy_host_ledger_is_imported_once_in_its_original_context(fluid, root):
    from webfluid.core.ext import db
    from sqlalchemy import select, delete
    from wf_peering.models.ledger import LedgerEntry
    from wf_peering.protocol import entries, network
    from wf_peering.protocol.canonical import canonical_text
    from wf_peering.protocol.signing import Signer
    from wf_peering.services import StateService
    from fluid.models import NetAppEntry
    from fluid.utils.legacy import LegacyMigration, MARKER

    assert (await LegacyMigration.run())["status"] in ("empty", "imported")
    host = Signer.generate()
    prev = entries.GENESIS
    rows = []
    for seq in range(1, 6):
        content = entries.make(seq, prev, "shop:order", "shop", { "n": seq }, ts="2026-10-01T00:00:00Z",
                               subject="acct:alice")
        value = entries.entry_hash(content)
        rows.append(LedgerEntry(seq, value, entries.entry_leaf(content), prev, content["kind"], "shop", "acct:alice",
                                None, content["ts"], canonical_text(content),
                                entries.sign_hash(host, entries.LEDGER_CONTEXT, value), content["ts"]))
        prev = value
    async with db.async_executor(model=LedgerEntry) as e:
        await e.exec(delete(LedgerEntry), scalars=False)
        for row in rows: await e.insert(row)
    await StateService.set("host_key", host.public_key)
    await StateService.set(MARKER, None)
    first = await LegacyMigration.run()
    app = network.app_id(host.public_key)
    assert first["status"] == "imported" and first["imported"] == 5 and first["app"] == app
    assert first["context"] == "wf-ledger-v1"
    await StateService.set(MARKER, None)
    again = await LegacyMigration.run()
    assert again["status"] == "imported" and again["imported"] == 0
    async with db.async_executor(model=NetAppEntry) as e:
        stored = list((await e.exec(select(NetAppEntry).where(NetAppEntry.app == app))).all())
    assert [row.seq for row in stored] == [1, 2, 3, 4, 5]
    assert all(entries.verify_hash(host.public_key, entries.LEDGER_CONTEXT, row.hash, row.signature) for row in stored)

    async with db.async_executor(model=NetAppEntry) as e:
        await e.exec(delete(NetAppEntry).where(NetAppEntry.app == app), scalars=False)
    async with db.async_executor(model=LedgerEntry) as e:
        broken = (await e.exec(select(LedgerEntry).where(LedgerEntry.seq == 4))).first()
        broken.signature = rows[0].signature
    await StateService.set(MARKER, None)
    failed = await LegacyMigration.run()
    assert failed["status"] == "failed" and failed["reason"] == "INVALID_SIGNATURE_4"
    async with db.async_executor(model=NetAppEntry) as e:
        assert list((await e.exec(select(NetAppEntry).where(NetAppEntry.app == app))).all()) == []

    export = await LegacyMigration.export(root / "exports" / "legacy.json")
    data = json.loads(export.read_text(encoding="utf-8"))
    assert data["format"] == "wf-peering-legacy-export-1" and data["inventory"]["counts"]["ledger"] == 5
    async with db.async_executor(model=LedgerEntry) as e:
        await e.exec(delete(LedgerEntry), scalars=False)
    await StateService.set("host_key", None)
    await StateService.set(MARKER, None)
    assert (await LegacyMigration.run())["status"] == "empty"
