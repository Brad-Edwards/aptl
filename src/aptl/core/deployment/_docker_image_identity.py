"""Canonical exact Docker image-identity parsing for realization checks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import re
from typing import Any

EXACT_IMAGE_INSPECT_FORMAT = (
    "{{json .RepoDigests}}\t{{.Id}}\t{{.Os}}/{{.Architecture}}"
    '{{with index . "Variant"}}/{{.}}{{end}}'
)
# What the selected daemon holds under one reference, read without a registry.
LOCAL_IMAGE_PRESENT = "present"
LOCAL_IMAGE_MISSING = "missing"
LOCAL_IMAGE_MISMATCHED = "digest-mismatched"
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

    canonical_digest = _canonical_repo_digest(image_ref)
    if canonical_digest is None:
        return None
    try:
        repo_digests_raw, image_id, platform_raw = (
            str(stdout or "").strip().split("\t", 2)
        )
        repo_digests = json.loads(repo_digests_raw)
    except (TypeError, ValueError):
        return None
    platform = normalized_platform(platform_raw)
    identity = None
    if (
        isinstance(repo_digests, list)
        and canonical_digest in repo_digests
        and bool(_IMAGE_ID.fullmatch(image_id))
        and platform is not None
    ):
        identity = ExactDockerImageIdentity(image_id=image_id, platform=platform)
    return identity


def is_exact_image_reference(image_ref: str) -> bool:
    """Whether a reference pins one immutable image by its sha256 digest.

    A tag alone is mutable, so it never proves which image a name resolves to.
    """

    return _canonical_repo_digest(image_ref) is not None


def local_image_state(run: Callable[..., Any], image_ref: str, *, timeout: int) -> str:
    """Read what the selected daemon holds under one reference (#953).

    An exact (digest-pinned) reference counts as present only when the
    daemon's own repo digests prove the pinned digest; resolving the name is
    not enough. Any other reference, such as a component built during backend
    preparation, only has to be present. ``run`` is the backend's list-form
    runner and this issues one local inspection, never a registry request.
    """

    exact = is_exact_image_reference(image_ref)
    output_format = ["--format", EXACT_IMAGE_INSPECT_FORMAT] if exact else []
    result = run(
        ["docker", "image", "inspect", *output_format, image_ref], timeout=timeout
    )
    state = LOCAL_IMAGE_PRESENT
    if result.returncode != 0:
        state = LOCAL_IMAGE_MISSING
    elif exact and exact_inspected_image_identity(result.stdout, image_ref) is None:
        state = LOCAL_IMAGE_MISMATCHED
    return state


def authored_tag_reference(image_ref: str) -> str | None:
    """Return the ``repository:tag`` a reference names, or ``None``.

    A reference may name a tag, a digest, or both. Only the last path segment
    can carry a tag, so a registry port -- the colon in ``localhost:5000/...``
    -- is never mistaken for one.
    """

    reference, separator, _digest = image_ref.rpartition("@")
    if not separator:
        reference = image_ref
    namespace, slash, image_name = reference.rpartition("/")
    name, colon, tag = image_name.partition(":")
    if not name or not colon or not tag:
        return None
    return f"{namespace}{slash}{name}:{tag}"


def _canonical_repo_digest(image_ref: str) -> str | None:
    """Normalize an immutable Docker reference to its inspected repo digest."""

    reference, separator, digest = image_ref.rpartition("@")
    namespace, slash, image_name = reference.rpartition("/")
    if not separator or not _IMAGE_ID.fullmatch(digest) or not image_name:
        return None
    # Docker records RepoDigests as repository@digest even when the requested
    # immutable reference also carries a human-readable tag before the @.
    return f"{namespace}{slash}{image_name.split(':', 1)[0]}@{digest}"
