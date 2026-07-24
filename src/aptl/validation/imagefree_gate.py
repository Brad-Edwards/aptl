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
        if node.runtime is not None:
            violations.extend(_runtime_coherence_violations(node))
        elif node.address not in imaged_addresses:
            violations.append(
                f"node {node.address} declares os={node.os!r} but has neither "
                f"declared runtime desired state nor a resolved image source: "
                f"its realization is undeclared in the SDL"
            )

    return violations


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
