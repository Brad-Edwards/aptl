"""Canonical package inputs for an optional image builder, without VM claims."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from aptl.appliance.input_images import (
    validate_image_sources as _validate_image_sources,
)
from aptl.appliance.payload_content import (
    archive_files,
    docker_archive_images,
    read_archive_member,
    validate_wheel_closure,
)
from aptl.core.assets import materialize, resolve_asset_source
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import PackIdentity, env_pack_bundle
from aptl.utils.deterministic_archive import deterministic_tarinfo, open_nofollow
from aptl.utils.deterministic_archive import hash_file_nofollow as _hash_file_nofollow
from aptl.validation.curated_live_proof import expected_bundle_matrix
from aptl.validation.participant_profile_models import (
    AssetLockEntry,
    ParticipantAssetLock,
)
from aptl.workbench.profiles import profile_for

# These are apparatus roles in addition to the model-derived scenario services.
# References are supplied from the image acquisition/build record and checked
# against Docker-save's config/layer bytes; mutable tags alone never suffice.
HELPER_ROLES = frozenset(
    {
        "helper.capture",
        "helper.boundary",
        "helper.traffic-mirror",
        "helper.egress",
        "helper.certs",
        "helper.suricata-seed",
        "child.shuffle-worker",
        "child.shuffle-http",
    }
)


class CanonicalInputs(BaseModel):
    """A software input contract; no disk, signature or qualification substitute."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["aptl.canonical-inputs/v1"]
    aptl_version: str
    scenario_pack: PackIdentity
    python_version: str
    architecture: Literal["x86_64", "aarch64"]
    runtime_prerequisites: dict[str, str]
    image_roles: dict[str, str]
    asset_lock: ParticipantAssetLock
    operating_system: Literal["linux"] = "linux"
    qualification: Literal["inputs-only"] = "inputs-only"


def hash_file_nofollow(path):
    """Use the incumbent streaming reader with the asset-lock hex encoding."""
    digest, size = _hash_file_nofollow(path)
    return digest.removeprefix("sha256:"), size


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _required_built_paths() -> set[str]:
    servers = {
        server.artifact_ref
        for role in ("red", "blue")
        for server in profile_for(role).servers
    }
    return {
        *servers,
        "mcp/mcp-reverse/build/index.js",
        "mcp/aptl-mcp-common/build/index.js",
        "web/build/index.html",
    }


def validate_canonical_inputs(staging: Path) -> CanonicalInputs:
    """Validate a closed platform-specific payload, including nested archives."""
    from aptl.appliance.offline import _release_environment, _validate_staged_paths

    _validate_staged_paths(staging)
    inputs = CanonicalInputs.model_validate_json((staging / "inputs.json").read_bytes())
    if _release_environment(staging) != ("techvault", inputs.aptl_version):
        raise ValueError("canonical release identity mismatch")
    if (
        platform.system() != "Linux"
        or inputs.python_version != platform.python_version()
        or inputs.architecture != platform.machine()
    ):
        raise ValueError("validate inputs on their declared Python/architecture target")
    project = archive_files(staging / "project.tar")
    image_files = archive_files(staging / "oci-images.tar")
    images = docker_archive_images(staging / "oci-images.tar", image_files)
    requirements = (staging / "requirements.txt").read_text()
    wheels = validate_wheel_closure(staging / "wheelhouse", requirements)
    for name in project:
        _admit_project_path(name)
    if not _required_built_paths() <= project.keys():
        raise ValueError("canonical frontend or MCP build is missing")
    for server in (
        "aptl-mcp-common",
        *(
            "mcp-" + name
            for name in (
                "red",
                "reverse",
                "indexer",
                "wazuh",
                "network",
                "soar",
                "casemgmt",
                "threatintel",
            )
        ),
    ):
        prefix = "mcp/" + server + "/"
        if prefix + "package-lock.json" not in project or not any(
            name.startswith(prefix + "node_modules/") for name in project
        ):
            raise ValueError("canonical MCP runtime dependency closure is missing")
    actual = {"project/" + name: digest for name, digest in project.items()}
    actual.update({"wheelhouse/" + name: digest for name, digest in wheels.items()})
    for path in staging.iterdir():
        if path.name not in {"wheelhouse", "inputs.json"}:
            actual[path.name] = hash_file_nofollow(path)[0]
    locked = {
        asset.source: asset.sha256
        for asset in inputs.asset_lock.assets
        if asset.kind != "image-id"
    }
    if (
        len(locked)
        != len(
            [asset for asset in inputs.asset_lock.assets if asset.kind != "image-id"]
        )
        or actual != locked
    ):
        raise ValueError("canonical input content differs from its asset lock")
    locked_images = {
        asset.source for asset in inputs.asset_lock.assets if asset.kind == "image-id"
    }
    if (
        set(images) != locked_images
        or set(inputs.image_roles.values()) != locked_images
    ):
        raise ValueError("canonical image closure differs from its asset lock")
    if not HELPER_ROLES <= inputs.image_roles.keys():
        raise ValueError("canonical helper/child-image identities are missing")
    with tempfile.TemporaryDirectory(prefix="aptl-input-pack-") as work:
        bundle = env_pack_bundle(Path(work))
        if bundle.pack_identity != inputs.scenario_pack:
            raise ValueError("canonical package identity differs from installed pack")
    _verify_packaged_project(staging, inputs, project, images, image_files)
    # Keep the wheel's immutable requirements export in the payload, so replacing
    # both a wheel and the top-level lock cannot silently change the closure.
    exported = read_archive_member(
        staging / "project.tar", "requirements/web.txt"
    ).decode()
    from aptl.appliance.payload_content import locked_requirements

    baseline = locked_requirements(exported)
    closure = locked_requirements(requirements)
    if {
        name: value for name, value in closure.items() if name != "aptl-labs"
    } != baseline:
        raise ValueError("wheel closure does not match the packaged dependency lock")
    return inputs


def _archive_project(project: Path, output: Path) -> dict[str, str]:
    """Archive fresh build inputs; flatten only contained npm dependency links."""
    files = {}
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(project.rglob("*")):
            if path.is_dir() or ".bin" in path.parts or "__pycache__" in path.parts:
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(project) or not resolved.is_file():
                raise ValueError("build output escapes canonical project")
            relative = path.relative_to(project).as_posix()
            _admit_project_path(relative)
            digest, size = hash_file_nofollow(resolved)
            info = deterministic_tarinfo(
                relative,
                is_dir=False,
                size=size,
                mode=0o755 if path.stat().st_mode & 0o111 else 0o644,
            )
            with open_nofollow(resolved) as handle:
                archive.addfile(info, handle)
            files[relative] = digest
    return files


def _entry(
    index: int, kind: str, source: str, sha256: str, services=()
) -> AssetLockEntry:
    return AssetLockEntry(
        asset_id=f"input-{index}",
        kind=kind,
        source=source,
        sha256=sha256,
        services=services,
    )


def stage_canonical_inputs(
    *, staging: Path, wheelhouse: Path, image_archive: Path, image_roles: dict[str, str]
) -> CanonicalInputs:
    """Build fresh wheel-supplied assets and write a verifiable input inventory.

    Run using the APTL wheel being delivered. Python wheels and the closed image
    archive must already be acquired; this command builds npm outputs from locks.
    """
    import aptl

    _, packaged = resolve_asset_source()
    if not packaged:
        raise ValueError("input assembly must run from the installed APTL wheel")
    if staging.exists():
        raise ValueError("input staging must be a new directory")
    image_files = archive_files(image_archive)
    images = docker_archive_images(image_archive, image_files)
    if (
        set(image_roles.values()) != set(images)
        or not HELPER_ROLES <= image_roles.keys()
    ):
        raise ValueError("provide exactly the scenario, helper and child image closure")
    staging.mkdir(mode=0o700, parents=True)
    with tempfile.TemporaryDirectory(prefix="aptl-input-build-") as work:
        work = Path(work)
        project = work / "project"
        materialize(project)
        bundle = env_pack_bundle(work / "packs")
        matrix = expected_bundle_matrix(project, AptlConfig(), bundle)
        if set(image_roles) != {
            *HELPER_ROLES,
            *("scenario." + name for name in matrix.expected_services),
        }:
            raise ValueError("image roles do not match full TechVault")
        _validate_image_sources(
            project, bundle, images, image_roles, image_archive, image_files
        )
        _build_outputs(project, work)
        shutil.copytree(wheelhouse, staging / "wheelhouse", symlinks=True)
        aptl_wheels = list(
            (staging / "wheelhouse").glob(f"aptl_labs-{aptl.__version__}-*.whl")
        )
        if len(aptl_wheels) != 1:
            raise ValueError("wheelhouse must contain the installed APTL version")
        requirement = (project / "requirements/web.txt").read_text()
        requirement += f"\naptl-labs[web]=={aptl.__version__} --hash=sha256:{hash_file_nofollow(aptl_wheels[0])[0]}\n"
        (staging / "requirements.txt").write_text(requirement)
        validate_wheel_closure(staging / "wheelhouse", requirement)
        _write_full_profile(project, bundle, matrix, image_roles)
        project_files = _archive_project(project, staging / "project.tar")
        shutil.copyfile(image_archive, staging / "oci-images.tar")
        (staging / "appliance-release.env").write_text(
            f"APTL_APPLIANCE_SCENARIO=techvault\nAPTL_APPLIANCE_VERSION={aptl.__version__}\n"
        )
        for name in ("aptl-appliance-first-boot", "aptl-appliance-first-boot.service"):
            shutil.copyfile(project / "appliance/guest" / name, staging / name)
        assets = []
        for path, digest in sorted(project_files.items()):
            assets.append(
                _entry(len(assets), "project-file", "project/" + path, digest)
            )
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                kind = "python-wheel" if path.suffix == ".whl" else "input-file"
                assets.append(
                    _entry(
                        len(assets),
                        kind,
                        path.relative_to(staging).as_posix(),
                        hash_file_nofollow(path)[0],
                    )
                )
        for image in sorted(images):
            assets.append(
                _entry(len(assets), "image-id", image, image.removeprefix("sha256:"))
            )
        inputs = CanonicalInputs(
            schema_version="aptl.canonical-inputs/v1",
            aptl_version=aptl.__version__,
            scenario_pack=bundle.pack_identity,
            python_version=platform.python_version(),
            architecture=platform.machine(),
            runtime_prerequisites={
                "node": "22",
                "openssh": "public-key forced-command support",
                "docker": "rootful Linux with nftables",
                "systemd": "guest service manager",
            },
            image_roles=image_roles,
            asset_lock=ParticipantAssetLock(
                schema_version="aptl.participant-asset-lock/v2",
                profile_id="techvault-full",
                profile_version=1,
                assets=tuple(assets),
            ),
        )
        (staging / "inputs.json").write_text(inputs.model_dump_json(indent=2) + "\n")
    return validate_canonical_inputs(staging)


def _build_outputs(project, work):
    import os

    env = {"PATH": os.environ["PATH"], "HOME": str(work), "LANG": "C.UTF-8"}
    with (work / "build.log").open("w") as log:
        subprocess.run(
            ["bash", str(project / "mcp/build-all-mcps.sh")],
            cwd=project,
            env=env,
            stdout=log,
            stderr=log,
            check=True,
            timeout=1800,
        )
        for args in (["npm", "ci"], ["npm", "run", "build"]):
            subprocess.run(
                args,
                cwd=project / "web",
                env=env,
                stdout=log,
                stderr=log,
                check=True,
                timeout=900,
            )
    _flatten_common_dependencies(project)


def _flatten_common_dependencies(project):
    # npm installs common's dependencies under its real directory, not under
    # the consumers. Preserve that closure when replacing each link: Node then
    # resolves the same versions from the relocated common package.
    for directory in sorted((project / "mcp").iterdir()):
        linked = directory / "node_modules/aptl-mcp-common"
        if linked.is_symlink():
            target = linked.resolve(strict=True)
            if not target.is_relative_to(project / "mcp"):
                raise ValueError("MCP dependency link escapes package")
            linked.unlink()
            shutil.copytree(target, linked, ignore=shutil.ignore_patterns(".bin"))


def _write_full_profile(project, bundle, matrix, image_roles):
    """Bind the installed full pack to the incumbent qualification machinery."""
    from aptl.validation.participant_profile_models import ParticipantProfileManifest
    from aptl_techvault.participant_smoke import FULL_TECHVAULT_SMOKE_OPERATIONS

    root = project / "participant-profiles/techvault-full-v1"
    root.mkdir(parents=True)
    profiles = tuple(profile_for(role) for role in ("red", "blue"))
    checks = []
    for operation in FULL_TECHVAULT_SMOKE_OPERATIONS:
        checks.append(
            dict(
                check_id=operation.check_id,
                capability_id=operation.check_id,
                kind="mcp-tool",
                subject_id=operation.server_id,
                operation_id=operation.tool_name,
                timeout_seconds=120,
            )
        )
    for bookmark in sorted(
        {ref for profile in profiles for ref in profile.bookmark_refs}
    ):
        checks.append(
            dict(
                check_id="browser." + bookmark,
                capability_id="browser." + bookmark,
                kind="browser-operation",
                subject_id=bookmark,
                operation_id="authenticated-browser-operation",
                timeout_seconds=60,
            )
        )
    for name, kind in (
        ("runtime", "runtime-surface"),
        ("capture", "evidence"),
        ("offline", "offline-assets"),
        ("resources", "resource-budget"),
    ):
        checks.append(
            dict(
                check_id="full." + name,
                capability_id="full." + name,
                kind=kind,
                subject_id="techvault",
                operation_id="verify-" + name,
                timeout_seconds=900,
            )
        )
    for client in ("claude", "codex"):
        checks.append(
            dict(
                check_id="host." + client,
                capability_id="host." + client,
                kind="client-transport",
                subject_id=client,
                operation_id="authenticated-client-tool-call-and-revocation",
                timeout_seconds=300,
            )
        )
    readiness = dict(
        schema_version="aptl.participant-readiness/v1",
        suite_id="techvault-full",
        version=1,
        checks=checks,
    )
    narrative = dict(
        schema_version="aptl.participant-narrative/v1",
        narrative_id="techvault-full",
        version=1,
        operations=[
            dict(
                operation_id=check["check_id"],
                classification="required",
                capability_id=check["capability_id"],
                channel="mcp"
                if check["kind"] == "mcp-tool"
                else "browser"
                if check["kind"] == "browser-operation"
                else "workflow",
                expected_result="The admitted operation succeeds with correlated capture and role authorization.",
            )
            for check in checks
        ],
    )
    refs = {}
    for name, document in (("narrative", narrative), ("readiness", readiness)):
        path = root / (name + ".json")
        path.write_text(json.dumps(document, indent=2) + "\n")
        refs[name] = dict(
            path=path.relative_to(project).as_posix(),
            sha256=hash_file_nofollow(path)[0],
        )
    refs["config"] = dict(
        path="aptl.json", sha256=hash_file_nofollow(project / "aptl.json")[0]
    )
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


def _admit_project_path(name: str) -> None:
    parts = Path(name).parts
    if (
        any(
            part
            in {
                ".aptl",
                ".git",
                ".env",
                "soc_certs",
                "lab-ssh",
                "wazuh_indexer_ssl_certs",
            }
            for part in parts
        )
        or name == ".mcp.json"
        or name.startswith("keys/")
    ):
        raise ValueError(
            "runtime identity or credentials must not enter canonical inputs"
        )


def _verify_packaged_project(staging, inputs, project, images, image_files):
    """Bind every immutable project asset to the delivered APTL wheel bytes."""
    from aptl.appliance.payload_content import locked_requirements
    from aptl.appliance.versioning import aptl_wheel_version

    wheels = [
        path
        for path in (staging / "wheelhouse").iterdir()
        if aptl_wheel_version(path.name) is not None
    ]
    if len(wheels) != 1 or aptl_wheel_version(wheels[0].name) != inputs.aptl_version:
        raise ValueError("canonical APTL wheel version differs")
    requirement = locked_requirements((staging / "requirements.txt").read_text()).get(
        "aptl-labs"
    )
    if requirement is None or requirement[0].extras != {"web"}:
        raise ValueError("canonical inputs require the complete web dependency closure")
    with open_nofollow(wheels[0]) as handle, zipfile.ZipFile(handle) as wheel:
        assets = {
            name.removeprefix("aptl/_labdata/"): name
            for name in wheel.namelist()
            if name.startswith("aptl/_labdata/") and not name.endswith("/")
        }
        if not assets or any(
            project.get(name) != _hash(wheel.read(member))
            for name, member in assets.items()
        ):
            raise ValueError("project assets differ from the delivered APTL wheel")
        with tempfile.TemporaryDirectory(prefix="aptl-input-matrix-") as work:
            root = Path(work)
            # Only canonical matrix inputs need materializing; never extract a tar.
            for name in assets:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(wheel.read(assets[name]))
            bundle = env_pack_bundle(root / "pack")
            _validate_image_sources(
                root,
                bundle,
                images,
                inputs.image_roles,
                staging / "oci-images.tar",
                image_files,
            )
            matrix = expected_bundle_matrix(root, AptlConfig(), bundle)
            if set(inputs.image_roles) != {
                *HELPER_ROLES,
                *("scenario." + name for name in matrix.expected_services),
            }:
                raise ValueError("canonical image roles do not match the full scenario")
    for name in ("aptl-appliance-first-boot", "aptl-appliance-first-boot.service"):
        if hash_file_nofollow(staging / name)[0] != project.get(
            "appliance/guest/" + name
        ):
            raise ValueError("first-boot input differs from the packaged script")
