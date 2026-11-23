from webfluid.core.ext import db
from sqlalchemy import select, func
from wf_peering.services import BindingService, IdentityService
from wf_peering.settings import settings

from ..models import NetApp, NetSource
from .clock import Clock


class StatusService:
    @staticmethod
    async def sources() -> list[dict]:
        async with db.async_executor(model=NetSource) as e:
            rows = list((await e.exec(select(NetSource).order_by(NetSource.node))).all())
        return [{ "node": row.node, "url": row.url, "cursor": row.cursor, "last_ok": row.last_ok,
                  "last_error": row.last_error, "failures": row.failures } for row in rows]

    @classmethod
    async def network_trust(cls) -> dict:
        from datetime import timedelta
        from wf_peering.protocol import network, operators as ops
        from .apps import AppRegistry
        from .chain import ChainService
        from .store import ObjectStore
        members = await ObjectStore.membership()
        if members is None:
            return { "masters": 0, "reachable": 0, "groups": 0, "unassigned": 0, "conflicts": 0, "declared": 0,
                     "operators": [] }
        masters = [member for member in members.masters() if member.revoked_at is None]
        limit = (Clock.now() - timedelta(seconds=3 * settings.net_interval + 60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        reachable = { row["node"] for row in await cls.sources() if row["last_ok"] and row["last_ok"] >= limit }
        reachable.add(IdentityService.node_id())
        assignment, _ = ops.normalize(AppRegistry.operators)
        grouping = ops.independent(assignment, [member.node for member in masters])
        latest, unresolved, _ = ops.declarations(await ObjectStore.objects(network.OPERATOR_CONTEXT), members,
                                                 members.net, Clock.now(), network.OPERATOR_MAX_AGE, network.CLOCK_SKEW)
        declaring = ops.declared([member.node for member in masters], latest, unresolved, {})
        group_of = { node: name for name, info in declaring["declared"].items() for node in info["nodes"] }
        operators = []
        for member in sorted(masters, key=lambda item: item.admitted_at):
            entry = latest.get(member.node)
            body = entry["body"] if entry else None
            operators.append({
                "node": member.node, "url": member.url, "admitted_at": member.admitted_at,
                "primary": member.node == members.primary, "reachable": member.node in reachable,
                "name": body["operator"]["name"] if body else None, "form": body["operator"]["form"] if body else None,
                "country": body["operator"]["country"] if body else None, "declared_at": body["ts"] if body else None,
                "seq": body["seq"] if body else None, "group": group_of.get(member.node),
                "basis": group_of.get(member.node, "").split(":", 1)[0] or None,
                "reason": unresolved.get(member.node) or (None if body else "OPERATOR_MISSING")
            })
        _, policy_conflicts, _ = await ObjectStore.policy()
        _, _, chain_conflicts = await ChainService.state()
        forks = 0
        for app in [member.app for member in members.members.values() if member.role == "app"]:
            by_seq = {}
            for item in await ObjectStore.objects(network.APP_HEAD_CONTEXT, app):
                by_seq.setdefault(item["body"]["seq"], set()).add((item["body"]["hash"], item["body"]["root"]))
            forks += sum(1 for values in by_seq.values() if len(values) > 1)
        return {
            "masters": len(masters), "reachable": len(reachable & { member.node for member in masters }),
            "groups": grouping["independent_groups"], "unassigned": len(grouping["unassigned"]),
            "conflicts": len(policy_conflicts) + len(chain_conflicts) + forks,
            "declared": declaring["declared_groups"], "operators": operators
        }

    @classmethod
    async def summary(cls) -> dict:
        from wf_peering.role import current
        from .apps import AppRegistry
        from .chain import ChainService
        from .store import ObjectStore
        binding = await BindingService.get()
        role = current()
        data = {
            "node": IdentityService.node_id(), "key": IdentityService.public_key(), "role": settings.role,
            "topology": role.topology.label, "url": settings.origin, "upstream": role.topology.upstream,
            "debug": settings.debug, "now": Clock.ts(), "software": role.software,
            "network": None, "anchor": None, "primary": None, "policy": None, "members": None, "apps": None,
            "chain": None, "sources": await cls.sources()
        }
        if binding is not None:
            members = await ObjectStore.membership()
            policy, conflicts, _ = await ObjectStore.policy()
            roles = {}
            for member in members.members.values():
                if member.revoked_at is None: roles[member.role] = roles.get(member.role, 0) + 1
            async with db.async_executor(model=NetApp) as e:
                total = (await e.exec(select(func.count(NetApp.app)), scalars=False)).scalar() or 0
            data.update(network=binding["net"], anchor=binding["anchor"], primary=members.primary,
                        entry=binding.get("entry"),
                        policy={ key: policy[key] for key in ("seq", "inactive_days", "attest_max_age", "min_groups") }
                        | { "conflicts": len(conflicts) }, members=roles,
                        apps={ "known": total, "active": len(await AppRegistry.active_apps()) },
                        chain=await ChainService.stats() if settings.is_master else None)
        data.update(await role.status())
        return data
