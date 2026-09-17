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
from aptl.core.scenario_bundle import ScenarioBundle
from aptl.validation.curated_live_proof import bundle_realization


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
                {"scenario." + service: reference for service in node.backend_services}
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
            "child.shuffle-worker": environment["SHUFFLE_WORKER_IMAGE"],
            "child.shuffle-http": environment["SHUFFLE_BASE_IMAGE_NAME"]
            + ":http_1.4.0",
        }
    )
    return references


def validate_image_sources(
    project: Path,
    bundle: ScenarioBundle,
    images: dict[str, tuple[str, ...]],
    roles: dict[str, str],
    image_archive: Path,
    image_files: dict[str, str],
) -> None:
    """Bind each canonical tag or manifest reference to its locked config bytes."""
    for role, reference in canonical_image_references(project, bundle).items():
        identity = roles.get(role)
        if "@sha256:" in reference:
            expected = registry_image_id(image_archive, image_files, reference)
            valid = identity == expected
        else:
            valid = reference in images.get(identity, ())
        if not valid:
            raise ValueError("canonical image reference differs from role " + role)
