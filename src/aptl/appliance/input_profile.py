"""Full packaged profile and its content-bound qualification inputs."""

from __future__ import annotations

import json
import platform
from collections import defaultdict
from pathlib import Path
from typing import Any

from aptl.appliance.payload_content import hash_file_nofollow
from aptl.core.scenario_bundle import ScenarioBundle
from aptl.validation.curated_live_proof import ExpectedMatrix
from aptl.validation.participant_mcp_smoke import resolve_participant_mcp_smoke_plan
from aptl.validation.participant_profile_models import (
    AssetLockEntry,
    ParticipantAssetLock,
)
from aptl.workbench.profiles import profile_for


def _entry(
    index: int, kind: str, source: str, sha256: str, services: tuple[str, ...] = ()
) -> AssetLockEntry:
    """Construct one uniquely numbered content-lock entry."""
    return AssetLockEntry(
        asset_id=f"input-{index}",
        kind=kind,
        source=source,
        sha256=sha256,
        services=services,
    )


def _profile_checks() -> list[dict[str, Any]]:
    """Describe the real tools, browser operations and delivery checks."""
    checks = []
    profiles = tuple(profile_for(role) for role in ("red", "blue"))
    for operation in resolve_participant_mcp_smoke_plan("techvault-full.techvault"):
        checks.append(
            {
                "check_id": operation.check_id,
                "capability_id": operation.check_id,
                "kind": "mcp-tool",
                "subject_id": operation.server_id,
                "operation_id": operation.tool_name,
                "timeout_seconds": 120,
            }
        )
    for bookmark in sorted(
        {ref for profile in profiles for ref in profile.bookmark_refs}
    ):
        checks.append(
            {
                "check_id": "browser." + bookmark,
                "capability_id": "browser." + bookmark,
                "kind": "browser-operation",
                "subject_id": bookmark,
                "operation_id": "authenticated-browser-operation",
                "timeout_seconds": 60,
            }
        )
    for name, kind in (
        ("runtime", "runtime-surface"),
        ("capture", "evidence"),
        ("offline", "offline-assets"),
        ("resources", "resource-budget"),
    ):
        checks.append(
            {
                "check_id": "full." + name,
                "capability_id": "full." + name,
                "kind": kind,
                "subject_id": "techvault",
                "operation_id": "verify-" + name,
                "timeout_seconds": 900,
            }
        )
    for client in ("claude", "codex"):
        checks.append(
            {
                "check_id": "host." + client,
                "capability_id": "host." + client,
                "kind": "client-transport",
                "subject_id": client,
                "operation_id": "authenticated-client-tool-call-and-revocation",
                "timeout_seconds": 300,
            }
        )
    return checks


def _profile_documents(
    project: Path, root: Path, checks: list[dict[str, Any]]
) -> dict[str, Any]:
    """Write and hash the narrative and readiness documents."""
    readiness = {
        "schema_version": "aptl.participant-readiness/v1",
        "suite_id": "techvault-full",
        "version": 1,
        "checks": checks,
    }
    narrative = {
        "schema_version": "aptl.participant-narrative/v1",
        "narrative_id": "techvault-full",
        "version": 1,
        "operations": [
            {
                "operation_id": check["check_id"],
                "classification": "required",
                "capability_id": check["capability_id"],
                "channel": "mcp"
                if check["kind"] == "mcp-tool"
                else "browser"
                if check["kind"] == "browser-operation"
                else "workflow",
                "expected_result": "The admitted operation succeeds with correlated capture and role authorization.",
            }
            for check in checks
        ],
    }
    refs = {}
    for name, document in (("narrative", narrative), ("readiness", readiness)):
        path = root / (name + ".json")
        path.write_text(json.dumps(document, indent=2) + "\n")
        refs[name] = {
            "path": path.relative_to(project).as_posix(),
            "sha256": hash_file_nofollow(path)[0],
        }
    refs["config"] = {
        "path": "aptl.json",
        "sha256": hash_file_nofollow(project / "aptl.json")[0],
    }
    return refs


def _profile_assets(
    project: Path,
    refs: dict[str, Any],
    matrix: ExpectedMatrix,
    image_roles: dict[str, str],
) -> tuple[AssetLockEntry, ...]:
    """Bind document, MCP artifact and scenario image content identities."""
    profiles = tuple(profile_for(role) for role in ("red", "blue"))
    assets = []
    for ref in refs.values():
        assets.append(_entry(len(assets), "project-file", ref["path"], ref["sha256"]))
    for profile in profiles:
        for server in profile.servers:
            assets.append(
                _entry(
                    len(assets),
                    "mcp-artifact",
                    server.artifact_ref,
                    hash_file_nofollow(project / server.artifact_ref)[0],
                )
            )
    image_services = defaultdict(list)
    for service in matrix.expected_services:
        image_services[image_roles["scenario." + service]].append(service)
    for image, services in sorted(image_services.items()):
        assets.append(
            _entry(
                len(assets),
                "image-id",
                image,
                image.removeprefix("sha256:"),
                tuple(services),
            )
        )
    return tuple(assets)


def _write_full_profile(
    project: Path,
    bundle: ScenarioBundle,
    matrix: ExpectedMatrix,
    image_roles: dict[str, str],
) -> None:
    """Bind the installed full pack to the incumbent qualification machinery."""
    from aptl.validation.participant_profile_models import ParticipantProfileManifest

    root = project / "participant-profiles/techvault-full-v1"
    root.mkdir(parents=True)
    checks = _profile_checks()
    refs = _profile_documents(project, root, checks)
    assets = _profile_assets(project, refs, matrix, image_roles)
    lock = ParticipantAssetLock(
        schema_version="aptl.participant-asset-lock/v2",
        profile_id="techvault-full",
        profile_version=1,
        assets=tuple(assets),
    )
    lock_path = root / "asset-lock.json"
    lock_path.write_text(lock.model_dump_json(indent=2) + "\n")
    # Limits are a release qualification contract, not measured claims. Actual
    # resource/offline/independent-machine evidence is still mandatory to seal.
    budgets = {
        "minimum_hardware": {
            "architecture": platform.machine(),
            "vcpus": 8,
            "memory_bytes": 32 * 1024**3,
            "disk_bytes": 250 * 1024**3,
        },
        "maximums": {
            "peak_cpu_percent": 95,
            "peak_memory_bytes": 28 * 1024**3,
            "staged_profile_assets_bytes": 100 * 1024**3,
            "unique_image_compressed_bytes": 60 * 1024**3,
            "unique_image_expanded_bytes": 100 * 1024**3,
            "peak_runtime_disk_bytes": 120 * 1024**3,
            "cold_start_seconds": 1800,
            "warm_start_seconds": 600,
            "clean_reset_seconds": 900,
        },
    }
    manifest = ParticipantProfileManifest(
        schema_version="aptl.participant-profile/v1",
        profile_id="techvault-full",
        version=1,
        **refs,
        scenario={
            "source": "env-pack",
            "identity": bundle.pack_identity,
            "path": bundle.sdl_path.relative_to(bundle.root).as_posix(),
            "sha256": hash_file_nofollow(bundle.sdl_path)[0],
        },
        capabilities={"workbench_profiles": ("red", "blue")},
        budgets=budgets,
        release_evidence={
            "asset_lock_schema": "aptl.participant-asset-lock/v2",
            "qualification_report_schema": "aptl.participant-qualification/v1",
            "asset_lock_ref": lock_path.relative_to(project).as_posix(),
            "asset_lock_sha256": hash_file_nofollow(lock_path)[0],
            "qualification_report_ref": "release/qualification/techvault-full-v1.json",
        },
    )
    (root / "profile.json").write_text(manifest.model_dump_json(indent=2) + "\n")
