"""Static image-free realization gate (ADR-048, #581 P7).

Asserts that a deployment realization is fully declared: every OS-bearing node
resolves either through the generic materializer (declared `runtime:`) or
through a trust-policy-resolved, transparently declared vendor `source:` (an
upstream image reference visible and traceable in the SDL - not a hidden,
APTL-authored appliance image). TechVault's real shape is permanently mixed
(some products are OS packages, others are only ever distributed as vendor
container images), so neither realization style alone is "the goal" - a node
relying on neither, with its actual definition living only in
docker-compose.yml with no SDL-declared realization at all, is the violation
this gate blocks on. It never consults docker-compose.yml itself.

A `runtime:` node also has its own internal coherence checked: a node that
declares service units must also declare the software those services need.
"""

from __future__ import annotations

from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


def image_free_violations(realization: DeploymentRealizationSpec) -> list[str]:
    """Return one message per realization-contract violation, empty when clean."""

    violations: list[str] = []
    imaged_addresses = {image.address for image in realization.images}

    for node in realization.nodes:
        if not node.os:
            continue
        if node.runtime is not None and _declares_any_state(node.runtime):
            violations.extend(_runtime_coherence_violations(node))
        elif node.address not in imaged_addresses:
            violations.append(
                f"node {node.address} declares os={node.os!r} but has neither "
                f"declared runtime desired state nor a resolved image source: "
                f"its realization is undeclared in the SDL"
            )

    return violations


# Every runtime dimension APTL can realize. A node that populates none of them
# has declared nothing, whatever the presence of a ``runtime`` block suggests.
_DECLARABLE_DIMENSIONS = (
    "packages",
    "software_components",
    "service_manager_units",
    "local_identity",
    "identity_authorities",
    "filesystem_inventory",
    "mounts",
    "environment",
    "forwarding_agents",
    "network_detection_engines",
    "security_monitoring_managers",
    "service_listeners",
    "processes",
    "scheduled_jobs",
)


def _declares_any_state(runtime: object) -> bool:
    """Whether a runtime block actually declares something to realize.

    ``runtime:`` being present is not a declaration. An empty block satisfies a
    "is there a runtime object" test while saying nothing about what the node
    contains, which is exactly the hollow node this gate exists to reject: right
    name, right ports, none of the behaviour.
    """

    return any(getattr(runtime, name, None) for name in _DECLARABLE_DIMENSIONS)


def _runtime_coherence_violations(node: DeploymentNodeRealization) -> list[str]:
    """Return violations internal to one node's declared runtime state."""

    units = node.runtime.service_manager_units
    packages = node.runtime.packages
    software = node.runtime.software_components
    if units and not (packages or software):
        names = ", ".join(sorted(u.unit_name for u in units))
        return [
            f"node {node.address} declares service units ({names}) but no "
            f"packages/software_components to provide them"
        ]
    return []


def assert_image_free(realization: DeploymentRealizationSpec) -> None:
    """Raise ``ImageFreeGateError`` when the realization violates the contract."""

    violations = image_free_violations(realization)
    if violations:
        raise ImageFreeGateError(violations)


class ImageFreeGateError(AssertionError):
    """Raised when a realization is not a clean image-free realization."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = list(violations)
        super().__init__(
            "image-free gate failed:\n  - " + "\n  - ".join(self.violations)
        )
