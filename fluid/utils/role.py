from wf_peering import NodeRole, __version__
from wf_peering.services import BindingService, IdentityService, JournalService
from wf_peering.settings import settings


class NetRole(NodeRole):
    shared_jobs = ("startup", "heartbeat", "activity", "retention")

    def __init__(self, topology, version: str | None = None, policy: dict | None = None, name: str = "webfluid",
                 retention_days: int = 90):
        self.topology = topology
        self.name = topology.role
        self.serves_ui = topology.role == "master"
        self.software = f"peering-app/{version or '0'} wf-peering/{__version__}"
        self.policy = policy
        self.network_name = name
        self.retention_days = retention_days

    async def startup(self) -> None:
        from .legacy import LegacyMigration
        from .link import UpstreamLink
        from .network import NetworkService
        await JournalService.append("peering:node-role", { "role": self.topology.label,
                                                          "upstream": self.topology.upstream })
        await LegacyMigration.run()
        if self.topology.role == "master":
            binding = await NetworkService.ensure(self.network_name, self.policy)
            if binding is not None:
                await NetworkService.maintain_policy(self.policy)
                from .operator import OperatorService
                await OperatorService.maintain()
        UpstreamLink.ensure()

    async def heartbeat(self) -> None:
        from .link import UpstreamLink
        UpstreamLink.ensure()

    async def retention(self) -> None:
        from .apps import AppRegistry
        from .network import NetworkService
        from .operator import OperatorService
        await NetworkService.prune_nonces()
        if await BindingService.network():
            await AppRegistry.retention(self.retention_days)
            await OperatorService.retention()

    async def status(self) -> dict:
        from .link import UpstreamLink
        binding = await BindingService.get()
        return {
            "topology": self.topology.label,
            "upstream": self.topology.upstream,
            "network": (binding or {}).get("net"),
            "anchor": (binding or {}).get("anchor"),
            "link": UpstreamLink.snapshot() if self.topology.upstream else None
        }

    async def checkpoint_basis(self, day, moment):
        return 0, "stale", { "status": "none" }
