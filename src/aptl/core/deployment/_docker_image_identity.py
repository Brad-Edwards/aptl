"""Canonical exact Docker image-identity parsing for realization checks."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re

EXACT_IMAGE_INSPECT_FORMAT = (
    "{{json .RepoDigests}}\t{{.Id}}\t{{.Os}}/{{.Architecture}}"
    "{{if .Variant}}/{{.Variant}}{{end}}"
)
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DockerPlatform:
    """Canonical Docker OS, architecture, and optional architecture variant."""

    os: str
    architecture: str
    variant: str = ""


@dataclass(frozen=True)
class ExactDockerImageIdentity:
    """Immutable daemon-local ID and platform for one exact repo digest."""

    image_id: str
    platform: DockerPlatform


def normalized_platform(value: object) -> DockerPlatform | None:
    """Normalize Docker platform aliases without losing variant semantics."""

    raw = str(value or "").strip().lower()
    parts = raw.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    os_name, architecture = parts[:2]
    variant = parts[2] if len(parts) > 2 else ""
    aliases = {
        "x86_64": ("amd64", ""),
        "aarch64": ("arm64", "v8"),
        "arm64": ("arm64", "v8"),
        "armv8l": ("arm", "v8"),
        "armv7l": ("arm", "v7"),
        "armhf": ("arm", "v7"),
        "armv6l": ("arm", "v6"),
        "i386": ("386", ""),
        "i686": ("386", ""),
    }
    architecture, inferred_variant = aliases.get(architecture, (architecture, ""))
    if not variant:
        variant = inferred_variant
    elif not variant.startswith("v") and architecture in {"arm", "arm64"}:
        variant = f"v{variant}"
    return DockerPlatform(os_name, architecture, variant)


def platform_is_compatible(daemon: DockerPlatform, image: DockerPlatform) -> bool:
    """Whether an image platform can run natively on the selected daemon."""

    if (daemon.os, daemon.architecture) != (image.os, image.architecture):
        return False
    return daemon.variant == image.variant


def exact_inspected_image_identity(
    stdout: object,
    image_ref: str,
) -> ExactDockerImageIdentity | None:
    """Parse identity only when inspection proves the requested repo digest."""

    try:
        repo_digests_raw, image_id, platform_raw = (
            str(stdout or "").strip().split("\t", 2)
        )
        repo_digests = json.loads(repo_digests_raw)
    except (TypeError, ValueError):
        return None
    platform = normalized_platform(platform_raw)
    if (
        not isinstance(repo_digests, list)
        or image_ref not in repo_digests
        or not _IMAGE_ID.fullmatch(image_id)
        or platform is None
    ):
        return None
    return ExactDockerImageIdentity(image_id=image_id, platform=platform)
