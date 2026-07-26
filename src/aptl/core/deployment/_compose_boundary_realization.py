"""Compose-side compilation and enforcement of independent boundary authorities."""

from __future__ import annotations

import ipaddress

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.deployment._compose_boundary import (
    DEFAULT_BOUNDARY_HELPER_IMAGE,
    realize_boundary as _realize_boundary,
)
from aptl.core.deployment._compose_realization_networks import (
    _match_managed_network,
)
from aptl.core.deployment.boundary import (
    AcesBoundarySpec,
    BoundaryEnforcementSpec,
    BoundaryNetwork,
    BoundaryWorkload,
)
from aptl.core.deployment.boundary_compiler import (
    BoundaryCompileError,
    compile_aces_boundary,
    compile_platform_boundary,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult


def _boundary_ip_families(
    subnets: list[object],
) -> tuple[str | None, str | None]:
    """Return the first observed IPv4 and IPv6 subnet without guessing."""

    ipv4: str | None = None
    ipv6: str | None = None
    for value in subnets:
        if not isinstance(value, str) or not value:
            continue
        try:
            version = ipaddress.ip_network(value, strict=False).version
        except ValueError as exc:
            raise BoundaryCompileError("boundary network subnet was invalid") from exc
        if version == 4 and ipv4 is None:
            ipv4 = value
        elif version == 6 and ipv6 is None:
            ipv6 = value
    return ipv4, ipv6


def _sorted_labels(raw: object) -> tuple[tuple[str, str], ...]:
    """Normalize an observed label mapping into deterministic string pairs."""

    if not isinstance(raw, dict):
        return ()
    return tuple(sorted((str(key), str(value)) for key, value in raw.items()))


def _network_observation(
    name: str,
    details: dict[str, object],
) -> BoundaryNetwork:
    """Build one strict network observation from bounded backend fields."""

    bridge = details.get("bridge")
    if not isinstance(bridge, str) or not bridge:
        raise BoundaryCompileError("realized network bridge was not observable")
    subnets = details.get("subnets")
    if not isinstance(subnets, list):
        subnets = [details.get("subnet", "")]
    ipv4, ipv6 = _boundary_ip_families(subnets)
    return BoundaryNetwork(
        name=name,
        bridge=bridge,
        ipv4_cidr=ipv4,
        ipv6_cidr=ipv6,
        labels=_sorted_labels(details.get("labels")),
    )


def _workload_addresses(
    attached: object,
    known_networks: set[str],
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    """Extract exact known-network addresses from one container inspection."""

    if not isinstance(attached, dict):
        return (), ()
    ipv4: list[tuple[str, str]] = []
    ipv6: list[tuple[str, str]] = []
    for network_name, network in attached.items():
        if network_name not in known_networks or not isinstance(network, dict):
            continue
        ipv4_address = network.get("IPAddress")
        if isinstance(ipv4_address, str) and ipv4_address:
            ipv4.append((network_name, ipv4_address))
        ipv6_address = network.get("GlobalIPv6Address")
        if isinstance(ipv6_address, str) and ipv6_address:
            ipv6.append((network_name, ipv6_address))
    return tuple(sorted(ipv4)), tuple(sorted(ipv6))


class ComposeBoundaryRealizationMixin:
    """Apply platform and ACES policy on the selected Compose daemon host."""

    def configure_appliance_boundary(
        self,
        policy: ApplianceBoundaryPolicy,
        binding: ApplianceBoundaryBinding,
    ) -> None:
        """Install trusted release and launcher projections for realization."""

        self._appliance_boundary = (policy, binding)
        self._boundary_helper_image = binding.boundary_helper_image

    def realize_boundary(self, policy: BoundaryEnforcementSpec) -> LabResult:
        """Apply and observe policy on the selected Docker daemon host."""

        result = _realize_boundary(
            self,
            policy,
            helper_image=self._boundary_helper_image,
        )
        if result.success:
            self._record_boundary_receipt(policy)
        return result

    def _record_boundary_receipt(self, policy: BoundaryEnforcementSpec) -> None:
        """Store only normalized enforcement identity needed by qualification."""

        if policy.authority == "aces" and not policy.rules:
            self._boundary_receipts.pop("aces", None)
            return
        binding = (
            self._appliance_boundary[1]
            if self._appliance_boundary is not None
            else None
        )
        source_digest = (
            policy.policy_digest
            if policy.authority == "platform"
            else (binding.aces_plan_digest if binding is not None else "")
        )
        self._boundary_receipts[policy.authority] = {
            "source_digest": source_digest,
            "enforcement_digest": policy.digest(),
            "families": ("bridge", "inet"),
            "default_deny": policy.authority == "platform",
        }

    def _realize_authority_boundaries(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Apply platform policy first, then the independent ACES authority."""

        platform = self._realize_platform_boundary()
        if platform is not None:
            return platform
        return self._realize_aces_boundary(realization)

    def _realize_platform_boundary(self) -> LabResult | None:
        """Compile and enforce the configured signed platform policy."""

        configured = getattr(self, "_appliance_boundary", None)
        if configured is None:
            return None
        policy, binding = configured
        try:
            networks = self._project_boundary_network_observations()
            workloads = self._platform_workload_observations(networks)
            enforcement = compile_platform_boundary(
                policy,
                policy_digest=binding.policy_digest,
                networks=networks,
                workloads=workloads,
                owner=self._project_name,
            )
        except BoundaryCompileError:
            return LabResult(
                success=False,
                error="Platform boundary anchors were not observed exactly.",
            )
        result = self.realize_boundary(enforcement)
        return None if result.success else result

    def _realize_aces_boundary(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Apply admitted ACES ACLs before a scenario workload can start."""

        if not realization.acls:
            configured = getattr(self, "_appliance_boundary", None)
            receipts = getattr(self, "_boundary_receipts", {})
            if configured is None and "aces" not in receipts:
                return None
            enforcement = AcesBoundarySpec.empty(self._project_name)
        else:
            try:
                networks = self._boundary_network_observations(realization)
                enforcement = compile_aces_boundary(
                    realization,
                    networks,
                    owner=self._project_name,
                )
            except BoundaryCompileError:
                return LabResult(
                    success=False,
                    error="ACES boundary could not be bound without widening policy.",
                )
        result = self.realize_boundary(enforcement)
        return None if result.success else result

    def _boundary_network_observations(
        self,
        realization: DeploymentRealizationSpec,
    ) -> tuple[BoundaryNetwork, ...]:
        """Return concrete bridge identities for scenario-declared networks."""

        if not realization.acls:
            return ()
        managed = set(self.host_list_lab_networks(self._project_name))
        observed: list[BoundaryNetwork] = []
        for desired in realization.networks:
            concrete = _match_managed_network(
                desired.name,
                managed,
                self._project_name,
            )
            details = self.host_inspect_network(concrete) if concrete else {}
            observed.append(_network_observation(desired.name, details))
        return tuple(observed)

    def _project_boundary_network_observations(
        self,
    ) -> tuple[BoundaryNetwork, ...]:
        """Observe all project-scoped platform networks."""

        observed = tuple(
            _network_observation(concrete, self.host_inspect_network(concrete))
            for concrete in sorted(self.host_list_lab_networks(self._project_name))
        )
        if not observed:
            raise BoundaryCompileError("platform networks were not observed")
        return observed

    def _platform_workload_observations(
        self,
        networks: tuple[BoundaryNetwork, ...],
    ) -> tuple[BoundaryWorkload, ...]:
        """Normalize exact labeled workload addresses without raw inspect output."""

        known = {network.name for network in networks}
        workloads: list[BoundaryWorkload] = []
        for row in self.host_list_lab_containers():
            name = row.get("name")
            labels = row.get("labels")
            if not isinstance(name, str) or not isinstance(labels, dict):
                continue
            details = self.container_inspect(name)
            network_settings = details.get("NetworkSettings", {})
            attached = (
                network_settings.get("Networks", {})
                if isinstance(network_settings, dict)
                else {}
            )
            ipv4, ipv6 = _workload_addresses(attached, known)
            if ipv4 or ipv6:
                workloads.append(
                    BoundaryWorkload(
                        identity=name,
                        labels=_sorted_labels(labels),
                        ipv4_by_network=ipv4,
                        ipv6_by_network=ipv6,
                    )
                )
        return tuple(sorted(workloads, key=lambda item: item.identity))
