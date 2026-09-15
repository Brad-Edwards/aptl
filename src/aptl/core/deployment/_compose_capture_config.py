"""Trusted Compose model and credential resolution for capture apparatus."""

from __future__ import annotations

from pathlib import Path

import yaml

from aptl.core.deployment._compose_stateful_model import artifact_source_path
from aptl.core.deployment._ssh_key_bundle import SSH_ACCESS_PROFILE_V1
from aptl.core.deployment.realization import DeploymentRealizationSpec

CAPTURE_COMPOSE_FILE = "docker-compose.capture.yml"
KALI_CAPTURE_APPARATUS_ID = "aptl.apparatus.kali-session-capture"
KALI_CAPTURE_SERVICE = "kali-capture"
KALI_CAPTURE_CONTAINER = "aptl-kali-capture"
KALI_CAPTURE_VOLUME = "kali_captures"
KALI_CONTAINER = "aptl-kali"
KALI_TRANSCRIPT_REGISTRATION = "aptl.collector.redteam-session-transcript"

_CAPTURE_BIND_TARGETS = {
    "/run/aptl-source/inner_key": "kali-pivot-private-key",
    "/run/aptl-source/outer_authorized_keys": "kali-authorized-keys",
}


def capture_requested(realization: DeploymentRealizationSpec) -> bool:
    """Return whether admission selected any capture apparatus."""

    return bool(realization.capture_apparatus)


def capture_credential_paths(
    realization: DeploymentRealizationSpec,
    realization_root: Path,
    *,
    require_files: bool,
) -> tuple[dict[str, Path], Path]:
    """Resolve the exact existing Kali credentials reused by the apparatus."""

    artifact = _capture_credential_artifact(realization)
    outputs = {item.name: item for item in artifact.outputs}
    if set(_CAPTURE_BIND_TARGETS.values()) - outputs.keys():
        raise ValueError("capture apparatus credential outputs are unavailable")
    source_root = artifact_source_path(realization_root, artifact).resolve()
    root = realization_root.resolve()
    sources = {
        target: _contained_capture_source(
            source_root / outputs[output_name].path,
            root,
            require_files=require_files,
        )
        for target, output_name in _CAPTURE_BIND_TARGETS.items()
    }
    pivot_public = _contained_capture_source(
        Path(f"{sources['/run/aptl-source/inner_key']}.pub"),
        root,
        require_files=require_files,
    )
    return sources, pivot_public


def _capture_credential_artifact(realization: DeploymentRealizationSpec) -> object:
    """Select the one exact SSH key bundle usable by the capture broker."""

    artifacts = [
        item
        for item in realization.generated_artifacts
        if item.generator == "ssh_key_bundle"
        and item.provenance == SSH_ACCESS_PROFILE_V1
    ]
    if len(artifacts) != 1:
        raise ValueError("capture apparatus requires one TechVault SSH bundle")
    return artifacts[0]


def _contained_capture_source(
    candidate: Path, root: Path, *, require_files: bool
) -> Path:
    """Resolve one broker credential while enforcing the realization root."""

    source = candidate.resolve()
    if not source.is_relative_to(root):
        raise ValueError("capture apparatus credential escaped realization root")
    if require_files and not source.is_file():
        raise ValueError("capture apparatus credential was not generated")
    return source


def capture_compose_file(
    project_dir: Path,
    realization: DeploymentRealizationSpec,
    realization_root: Path,
) -> Path:
    """Write the trusted apparatus model with engine-anchored local sources."""

    root = project_dir.resolve()
    source = root / CAPTURE_COMPOSE_FILE
    model = yaml.safe_load(source.read_text(encoding="utf-8"))
    service = model["services"][KALI_CAPTURE_SERVICE]
    service["build"]["context"] = str(root)
    sources, _pivot_public = capture_credential_paths(
        realization,
        realization_root,
        require_files=True,
    )
    for mount in service.get("volumes", ()):
        if mount.get("type") != "bind":
            continue
        path = sources.get(mount.get("target"))
        if path is None or not mount.get("read_only"):
            raise ValueError("invalid capture apparatus bind mount")
        mount["source"] = str(path)
    target = root / ".aptl" / "realization" / CAPTURE_COMPOSE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(model, sort_keys=True), encoding="utf-8", newline="\n"
    )
    return target


def capture_declaration_error(realization: DeploymentRealizationSpec) -> str | None:
    """Return a bounded error unless the immutable request is exactly supported."""

    error = None
    if capture_requested(realization):
        if len(realization.capture_apparatus) != 1:
            error = "aptl.capture-apparatus.unsupported-set"
        else:
            item = realization.capture_apparatus[0]
            supported = (
                item.apparatus_id == KALI_CAPTURE_APPARATUS_ID
                and item.service_name == KALI_CAPTURE_SERVICE
                and item.container_name == KALI_CAPTURE_CONTAINER
                and bool(item.governing_scopes)
                and item.environment_visible
            )
            if not supported:
                error = "aptl.capture-apparatus.unsupported-declaration"
    return error


__all__ = (
    "CAPTURE_COMPOSE_FILE",
    "KALI_CAPTURE_APPARATUS_ID",
    "KALI_CAPTURE_CONTAINER",
    "KALI_CAPTURE_SERVICE",
    "KALI_CAPTURE_VOLUME",
    "KALI_CONTAINER",
    "KALI_TRANSCRIPT_REGISTRATION",
    "capture_compose_file",
    "capture_credential_paths",
    "capture_declaration_error",
    "capture_requested",
)
