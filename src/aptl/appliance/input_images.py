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

_DIGEST_SEPARATOR = "@sha256:"
_PINNED_THIRD_PARTY_IMAGES = {
    "debian:13-slim": (
        "debian:13-slim@sha256:"
        "d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132"
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
    if not pinned.startswith(("aptl/", "aptl-")) and _DIGEST_SEPARATOR not in pinned:
        raise ValueError("canonical third-party image is not pinned by digest")
    return pinned


def runtime_image_tag(reference: str) -> str:
    """Return Docker's explicit runtime tag for a pinned registry reference."""

    name = reference.partition("@")[0]
    return name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"


def compose_runtime_image_aliases(
    project: Path, references: dict[str, str]
) -> dict[str, str]:
    """Bind authored Compose tags to the pinned images for their repositories."""

    pinned_by_repository: dict[str, str] = {}
    for reference in set(references.values()):
        if _DIGEST_SEPARATOR not in reference:
            continue
        repository = runtime_image_tag(reference).rsplit(":", 1)[0]
        previous = pinned_by_repository.setdefault(repository, reference)
        if previous != reference:
            raise ValueError("canonical pinned image repository is ambiguous")
    if not pinned_by_repository:
        return {}

    services = yaml.safe_load((project / "docker-compose.yml").read_text())["services"]
    if not isinstance(services, dict):
        raise ValueError("canonical Compose services are invalid")
    aliases: dict[str, str] = {}
    for service in services.values():
        if not isinstance(service, dict) or not isinstance(service.get("image"), str):
            continue
        tag = runtime_image_tag(service["image"])
        pinned = pinned_by_repository.get(tag.rsplit(":", 1)[0])
        if pinned is not None:
            aliases[tag] = pinned
    return aliases


def _scenario_image_references(realization) -> dict[str, str]:
    """Collect the image selected for every realized scenario service."""

    references = {}
    for node in realization.nodes:
        reference = (
            node.image.image_ref
            if node.image is not None
            else base_container_spec(
                node.address,
                os=node.os,
                os_version=node.os_version,
                runtime=node.runtime,
                options=NodePlanningOptions(
                    backend_base_image_ref=node.backend_base_image_ref
                ),
            ).image_ref
        )
        if reference:
            references.update(
                {
                    "scenario." + service: _pin_third_party(reference)
                    for service in node.backend_services
                }
            )
    return references


def _shuffle_child_images(project: Path, realization) -> dict[str, str]:
    """Validate and return the workflow engine's authored child images."""

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
    authorities = [
        authority
        for authority in orchestrator.runtime.orchestration_authorities
        if authority.orchestration_authority_id == "shuffle-orborus"
    ]
    if len(authorities) != 1:
        raise ValueError("canonical workflow child authority is ambiguous")
    templates = {
        template.template_id: template.image_ref
        for template in authorities[0].spawn_templates
    }
    if set(templates) != {"shuffle-worker", "shuffle-http-1-4-0"}:
        raise ValueError("canonical workflow child image inventory needs updating")
    if environment["SHUFFLE_WORKER_IMAGE"] != templates["shuffle-worker"]:
        raise ValueError("canonical workflow worker image differs from spawn template")
    if (
        runtime_image_tag(templates["shuffle-http-1-4-0"])
        != environment["SHUFFLE_BASE_IMAGE_NAME"] + ":http_1.4.0"
    ):
        raise ValueError("canonical workflow HTTP image differs from spawn template")
    return {
        "child.shuffle-worker": templates["shuffle-worker"],
        "child.shuffle-http": templates["shuffle-http-1-4-0"],
    }


def _certificate_generator_image(project: Path) -> str:
    """Return the single authored certificate helper image."""

    certificates = yaml.safe_load((project / "generate-indexer-certs.yml").read_text())
    generators = {service["image"] for service in certificates["services"].values()}
    if len(generators) != 1:
        raise ValueError("certificate helper image inventory is ambiguous")
    return generators.pop()


def canonical_image_references(project: Path, bundle: ScenarioBundle) -> dict[str, str]:
    """Read scenario references and authored child images from canonical sources."""

    realization = bundle_realization(project, AptlConfig(), bundle)
    references = _scenario_image_references(realization)
    references.update(
        {
            "helper.capture": "aptl-kali-capture:latest",
            "helper.boundary": DEFAULT_BOUNDARY_HELPER_IMAGE,
            "helper.traffic-mirror": DEFAULT_BOUNDARY_HELPER_IMAGE,
            "helper.egress": "aptl-appliance-egress-proxy:1",
            "helper.certs": _certificate_generator_image(project),
            "helper.suricata-seed": CONTENT_SEEDER_IMAGE,
            "helper.operator-access": OPERATOR_ACCESS_IMAGE,
            "helper.generic-samba-ad-base": "aptl/generic-samba-ad-base:latest",
            "helper.generic-systemd-base": "aptl/generic-systemd-base:latest",
            "helper.generic-systemd-base-debian": (
                "aptl/generic-systemd-base-debian:latest"
            ),
            **_shuffle_child_images(project, realization),
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
    references = canonical_image_references(project, bundle)
    for role, reference in references.items():
        identity = roles.get(role)
        if _DIGEST_SEPARATOR in reference:
            expected = registry_image_id(
                image_archive,
                image_files,
                reference,
                architecture=architecture,
            )
            valid = identity == expected and runtime_image_tag(reference) in images.get(
                identity, ()
            )
        else:
            valid = reference in images.get(identity, ())
        if not valid:
            raise ValueError("canonical image reference differs from role " + role)
    for tag, reference in compose_runtime_image_aliases(project, references).items():
        identity = registry_image_id(
            image_archive, image_files, reference, architecture=architecture
        )
        if tag not in images.get(identity, ()):
            raise ValueError(
                "canonical Compose runtime tag differs from pinned image " + tag
            )
