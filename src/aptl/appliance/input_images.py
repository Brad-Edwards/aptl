"""Canonical image references behind the full-TechVault input inventory."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from aptl.appliance.payload_content import registry_image_id
from aptl.backends.raes_base_substrate import NodePlanningOptions, base_container_spec
from aptl.core.config import AptlConfig
from aptl.core.deployment._compose_boundary import DEFAULT_BOUNDARY_HELPER_IMAGE
from aptl.core.deployment._compose_content_realization import CONTENT_SEEDER_IMAGE
from aptl.core.deployment._operator_access_endpoints import OPERATOR_ACCESS_IMAGE
from aptl.core.scenario_bundle import ScenarioBundle
from aptl.validation.curated_live_proof import bundle_realization

_PINNED_THIRD_PARTY_IMAGES = {
    "debian:13-slim": (
        "debian:13-slim@sha256:"
        "d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132"
    ),
    "frikky/shuffle:http_1.4.0": (
        "frikky/shuffle:http_1.4.0@sha256:"
        "011607c986960998c9c0ee4f7c3261319233148fe205177f0b7c2708a9d8e495"
    ),
    "jasonish/suricata:7.0": (
        "jasonish/suricata:7.0@sha256:"
        "0364b6f31192bc27a84dd471f60de22781d88e4d9511fbd3413e56ba4e150ac8"
    ),
    "wazuh/wazuh-certs-generator:0.0.2": (
        "wazuh/wazuh-certs-generator:0.0.2@sha256:"
        "88c4b30ad9b8320ba29f0a891761ad8000866c15c844d27b04974f5cb427c8f0"
    ),
}


def _pin_third_party(reference: str) -> str:
    """Require immutable registry identities for every non-APTL image."""

    pinned = _PINNED_THIRD_PARTY_IMAGES.get(reference, reference)
    if not pinned.startswith(("aptl/", "aptl-")) and "@sha256:" not in pinned:
        raise ValueError("canonical third-party image is not pinned by digest")
    return pinned


def canonical_image_references(project: Path, bundle: ScenarioBundle) -> dict[str, str]:
    """Read scenario references and authored child images from canonical sources."""
    realization = bundle_realization(project, AptlConfig(), bundle)
    references = {}
    for node in realization.nodes:
        if node.image is not None:
            reference = node.image.image_ref
        else:
            reference = base_container_spec(
                node.address,
                os=node.os,
                os_version=node.os_version,
                runtime=node.runtime,
                options=NodePlanningOptions(
                    backend_base_image_ref=node.backend_base_image_ref
                ),
            ).image_ref
        if reference:
            references.update(
                {
                    "scenario." + service: _pin_third_party(reference)
                    for service in node.backend_services
                }
            )
    orchestrator = next(
        node for node in realization.nodes if node.name == "shuffle-orborus"
    )
    environment = {item.name: item.value for item in orchestrator.runtime.environment}
    seed = (project / "scripts/seed-shuffle.sh").read_text()
    apps = set(
        re.findall(
            r'"app_name":\s*"([a-z0-9_-]+)",\s*"app_version":\s*"([0-9.]+)"', seed
        )
    )
    if apps != {("http", "1.4.0")}:
        raise ValueError("canonical workflow child image inventory needs updating")
    certificates = yaml.safe_load((project / "generate-indexer-certs.yml").read_text())
    generators = {service["image"] for service in certificates["services"].values()}
    if len(generators) != 1:
        raise ValueError("certificate helper image inventory is ambiguous")
    references.update(
        {
            "helper.capture": "aptl-kali-capture:latest",
            "helper.boundary": DEFAULT_BOUNDARY_HELPER_IMAGE,
            "helper.traffic-mirror": DEFAULT_BOUNDARY_HELPER_IMAGE,
            "helper.egress": "aptl-appliance-egress-proxy:1",
            "helper.certs": generators.pop(),
            "helper.suricata-seed": CONTENT_SEEDER_IMAGE,
            "helper.operator-access": OPERATOR_ACCESS_IMAGE,
            "helper.generic-samba-ad-base": "aptl/generic-samba-ad-base:latest",
            "helper.generic-systemd-base": "aptl/generic-systemd-base:latest",
            "helper.generic-systemd-base-debian": (
                "aptl/generic-systemd-base-debian:latest"
            ),
            "child.shuffle-worker": environment["SHUFFLE_WORKER_IMAGE"],
            "child.shuffle-http": environment["SHUFFLE_BASE_IMAGE_NAME"]
            + ":http_1.4.0",
        }
    )
    return {role: _pin_third_party(reference) for role, reference in references.items()}


def validate_image_sources(
    project: Path,
    bundle: ScenarioBundle,
    images: dict[str, tuple[str, ...]],
    roles: dict[str, str],
    image_archive: Path,
    image_files: dict[str, str],
    *,
    architecture: str | None = None,
) -> None:
    """Bind each canonical tag or manifest reference to its locked config bytes."""
    for role, reference in canonical_image_references(project, bundle).items():
        identity = roles.get(role)
        if "@sha256:" in reference:
            expected = registry_image_id(
                image_archive,
                image_files,
                reference,
                architecture=architecture,
            )
            valid = identity == expected
        else:
            valid = reference in images.get(identity, ())
        if not valid:
            raise ValueError("canonical image reference differs from role " + role)
