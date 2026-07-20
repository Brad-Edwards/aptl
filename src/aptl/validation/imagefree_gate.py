"""Static image-free realization gate (ADR-047, #581 P7).

Asserts that a deployment realization is fully image-free and coherent: no
appliance image, every OS-bearing node declares runtime desired state, and every
node that declares service units also declares the software those services need.
The gate is scenario-generic; it is the blocking static check the operational
TechVault cutover must pass. It never consults docker-compose.yml.
"""

from __future__ import annotations

from aptl.core.deployment.realization import DeploymentRealizationSpec


def image_free_violations(realization: DeploymentRealizationSpec) -> list[str]:
    """Return one message per image-free contract violation, empty when clean."""

    violations: list[str] = []

    if not realization.image_free:
        violations.append(
            "realization is not image-free: an appliance image or an "
            "OS-bearing node without declared runtime remains on the operational path"
        )

    for node in realization.nodes:
        if not node.os:
            continue
        if node.runtime is None:
            violations.append(
                f"node {node.address} declares os={node.os!r} but no runtime "
                f"desired state to materialize"
            )
            continue
        units = node.runtime.service_manager_units
        packages = node.runtime.packages
        software = node.runtime.software_components
        if units and not (packages or software):
            names = ", ".join(sorted(u.unit_name for u in units))
            violations.append(
                f"node {node.address} declares service units ({names}) but no "
                f"packages/software_components to provide them"
            )

    return violations


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
