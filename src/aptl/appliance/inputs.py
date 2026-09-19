"""Canonical package inputs for an optional image builder, without VM claims."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aptl.appliance.input_images import (
    canonical_image_references,
    runtime_image_tag,
    validate_image_sources as _validate_image_sources,
)
from aptl.appliance.input_profile import _entry, _write_full_profile
from aptl.appliance.payload_content import (
    archive_files,
    docker_archive_images,
    read_archive_member,
    registry_image_id,
    validate_wheel_closure,
)
from aptl.core.assets import materialize, resolve_asset_source
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import PackIdentity, env_pack_bundle
from aptl.utils.deterministic_archive import deterministic_tarinfo, open_nofollow
from aptl.utils.deterministic_archive import hash_file_nofollow as _hash_file_nofollow
from aptl.utils.strict_json import model_validate_json_strict
from aptl.validation.curated_live_proof import expected_bundle_matrix
from aptl.validation.participant_profile_models import (
    AssetLockEntry,
    ParticipantAssetLock,
)
from aptl.workbench.profiles import profile_for

INPUTS_RECORD = "inputs.json"
PROJECT_ARCHIVE = "project.tar"
IMAGE_ARCHIVE = "oci-images.tar"
REQUIREMENTS_FILE = "requirements.txt"
SYSTEM_PACKAGES_DIRECTORY = "system-packages"
SYSTEM_PACKAGES_LOCK = "system-packages.sha256"
_SYSTEM_PACKAGE_LINE = re.compile(
    r"^(?P<sha256>[0-9a-f]{64}) {2}(?P<filename>[A-Za-z0-9.+%:~_-]+\.deb)$"
)

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
        "helper.operator-access",
        "helper.generic-samba-ad-base",
        "helper.generic-systemd-base",
        "helper.generic-systemd-base-debian",
        "child.shuffle-worker",
        "child.shuffle-http",
    }
)


def _resolve_archive_image_roles(
    references: dict[str, str],
    images: dict[str, tuple[str, ...]],
    image_archive: Path,
    image_files: dict[str, str],
) -> dict[str, str]:
    """Resolve roles to saved config identities, independent of Docker's store."""

    resolved: dict[str, str] = {}
    for reference in sorted(set(references.values())):
        if "@sha256:" in reference:
            identity = registry_image_id(image_archive, image_files, reference)
            if runtime_image_tag(reference) not in images.get(identity, ()):
                raise ValueError("pinned Docker runtime tag is missing or differs")
        else:
            matches = [
                identity for identity, tags in images.items() if reference in tags
            ]
            if len(matches) != 1:
                raise ValueError("saved Docker tag is missing or ambiguous")
            identity = matches[0]
        resolved[reference] = identity
    return {role: resolved[reference] for role, reference in references.items()}


def acquire_canonical_images(
    *, image_archive: Path, image_roles: Path
) -> dict[str, str]:
    """Resolve and save the complete wheel-authored TechVault image closure."""

    _, packaged = resolve_asset_source()
    if not packaged:
        raise ValueError("image acquisition must run from the installed APTL wheel")
    if any(path.exists() or path.is_symlink() for path in (image_archive, image_roles)):
        raise ValueError("image acquisition outputs must be new")
    image_archive.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    image_roles.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aptl-image-acquire-") as work:
        project = Path(work) / "project"
        materialize(project)
        bundle = env_pack_bundle(Path(work) / "packs")
        references = canonical_image_references(project, bundle)
        for reference in sorted(set(references.values())):
            inspected = subprocess.run(
                ["docker", "image", "inspect", reference],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if inspected.returncode != 0:
                subprocess.run(
                    ["docker", "pull", reference],
                    check=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3600,
                )
                subprocess.run(
                    ["docker", "image", "inspect", reference],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
        pinned_runtime_tags = {
            runtime_image_tag(reference): reference
            for reference in references.values()
            if "@sha256:" in reference
        }
        for runtime_tag, pinned_reference in sorted(pinned_runtime_tags.items()):
            pinned_id = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", pinned_reference],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout.strip()
            if not pinned_id:
                raise ValueError("pinned Docker image identity is missing")
            tagged = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", runtime_tag],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if tagged.returncode != 0:
                subprocess.run(
                    ["docker", "tag", pinned_reference, runtime_tag],
                    check=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=60,
                )
            elif tagged.stdout.strip() != pinned_id:
                raise ValueError("Docker runtime tag differs from pinned image")
        save_references = set(references.values()) | set(pinned_runtime_tags)
        subprocess.run(
            [
                "docker",
                "save",
                "--output",
                str(image_archive),
                *sorted(save_references),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=7200,
        )
        image_files = archive_files(image_archive)
        images = docker_archive_images(image_archive, image_files)
        roles = _resolve_archive_image_roles(
            references, images, image_archive, image_files
        )
        if set(roles.values()) != set(images):
            raise ValueError("saved Docker archive differs from resolved image closure")
        _validate_image_sources(
            project, bundle, images, roles, image_archive, image_files
        )
    image_roles.write_text(json.dumps(roles, indent=2, sort_keys=True) + "\n")
    return roles


class CanonicalInputs(BaseModel):
    """A software input contract; no disk, signature or qualification substitute."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["aptl.canonical-inputs/v1"]
    aptl_version: str
    scenario_pack: PackIdentity
    python_version: str = Field(pattern=r"^3\.\d{1,2}$")
    architecture: Literal["x86_64", "aarch64"]
    runtime_prerequisites: dict[str, str]
    image_roles: dict[str, str]
    asset_lock: ParticipantAssetLock
    operating_system: Literal["linux"] = "linux"
    qualification: Literal["inputs-only"] = "inputs-only"


def hash_file_nofollow(path: Path) -> tuple[str, int]:
    """Use the incumbent streaming reader with the asset-lock hex encoding."""
    digest, size = _hash_file_nofollow(path)
    return digest.removeprefix("sha256:"), size


def _expected_system_packages(lock: Path, architecture: str) -> dict[str, str]:
    """Read the byte lock and reject mixed-architecture package sets."""

    lines = lock.read_text(encoding="utf-8").splitlines()
    expected: dict[str, str] = {}
    for line in lines:
        match = _SYSTEM_PACKAGE_LINE.fullmatch(line)
        if match is None or match["filename"] in expected:
            raise ValueError("guest system package lock is invalid")
        expected[match["filename"]] = match["sha256"]
    machine_architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(architecture)
    if (
        not expected
        or machine_architecture is None
        or any(
            not name.endswith((f"_{machine_architecture}.deb", "_all.deb"))
            for name in expected
        )
    ):
        raise ValueError("guest system package architecture is invalid")
    return expected


def validate_system_packages(
    packages: Path, lock: Path, *, architecture: str
) -> dict[str, str]:
    """Validate an exact offline Debian package closure against its byte lock."""

    if packages.is_symlink() or not packages.is_dir() or lock.is_symlink():
        raise ValueError("guest system package closure is invalid")
    expected = _expected_system_packages(lock, architecture)
    actual: dict[str, str] = {}
    for path in packages.iterdir():
        if path.is_symlink() or not path.is_file() or path.name not in expected:
            raise ValueError("guest system package closure contains an extra input")
        actual[path.name] = hash_file_nofollow(path)[0]
    if actual != expected:
        raise ValueError("guest system package closure differs from its lock")
    for required in ("docker.io_", "nodejs_", "openssh-server_"):
        if sum(name.startswith(required) for name in expected) != 1:
            raise ValueError("guest system package closure is incomplete")
    return actual


def _hash(data: bytes) -> str:
    """Hash immutable input bytes using the asset-lock encoding."""
    return hashlib.sha256(data).hexdigest()


def _required_built_paths() -> set[str]:
    """Collect every frontend and MCP entry point required by the payload."""
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


def validate_canonical_inputs(
    staging: Path, *, enforce_runtime_target: bool = True
) -> CanonicalInputs:
    """Validate a closed platform-specific payload, including nested archives."""
    from aptl.appliance.offline import _release_environment, _validate_staged_paths

    _validate_staged_paths(staging)
    inputs = model_validate_json_strict(
        CanonicalInputs, (staging / INPUTS_RECORD).read_bytes()
    )
    if _release_environment(staging) != ("techvault", inputs.aptl_version):
        raise ValueError("canonical release identity mismatch")
    running_python = ".".join(platform.python_version().split(".")[:2])
    if enforce_runtime_target and (
        platform.system() != "Linux"
        or inputs.python_version != running_python
        or inputs.architecture != platform.machine()
    ):
        raise ValueError("validate inputs on their declared Python/architecture target")
    project = archive_files(staging / PROJECT_ARCHIVE)
    image_files = archive_files(staging / IMAGE_ARCHIVE)
    images = docker_archive_images(
        staging / IMAGE_ARCHIVE,
        image_files,
        architecture=inputs.architecture,
    )
    requirements = (staging / REQUIREMENTS_FILE).read_text()
    wheels = validate_wheel_closure(
        staging / "wheelhouse",
        requirements,
        python_version=inputs.python_version,
        architecture=inputs.architecture,
    )
    system_packages = validate_system_packages(
        staging / SYSTEM_PACKAGES_DIRECTORY,
        staging / SYSTEM_PACKAGES_LOCK,
        architecture=inputs.architecture,
    )
    _validate_project_runtime(project)
    _validate_asset_lock(staging, inputs, project, wheels, system_packages, images)
    with tempfile.TemporaryDirectory(prefix="aptl-input-pack-") as work:
        bundle = env_pack_bundle(Path(work))
        if bundle.pack_identity != inputs.scenario_pack:
            raise ValueError("canonical package identity differs from installed pack")
    _verify_packaged_project(staging, inputs, project, images, image_files)
    # Keep the wheel's immutable requirements export in the payload, so replacing
    # both a wheel and the top-level lock cannot silently change the closure.
    exported = read_archive_member(
        staging / PROJECT_ARCHIVE, "requirements/web.txt"
    ).decode()
    from aptl.appliance.payload_content import locked_requirements

    baseline = locked_requirements(
        exported,
        python_version=inputs.python_version,
        architecture=inputs.architecture,
    )
    closure = locked_requirements(
        requirements,
        python_version=inputs.python_version,
        architecture=inputs.architecture,
    )
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
            if (
                path.is_dir()
                or ".bin" in path.parts
                or "node_gyp_bins" in path.parts
                or "__pycache__" in path.parts
            ):
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


@dataclass(frozen=True)
class CanonicalBuildTarget:
    """Optional Python and architecture target for an input build."""

    python_version: str | None = None
    architecture: str | None = None


def _write_wheel_requirements(
    staging: Path, project: Path, python_target: str, architecture_target: str
) -> None:
    """Bind the installed wheel to the guest's offline web closure."""

    import aptl

    aptl_wheels = list(
        (staging / "wheelhouse").glob(f"aptl_labs-{aptl.__version__}-*.whl")
    )
    if len(aptl_wheels) != 1:
        raise ValueError("wheelhouse must contain the installed APTL version")
    requirement = (project / "requirements/web.txt").read_text()
    requirement += f"\naptl-labs[web]=={aptl.__version__} --hash=sha256:{hash_file_nofollow(aptl_wheels[0])[0]}\n"
    (staging / REQUIREMENTS_FILE).write_text(requirement)
    validate_wheel_closure(
        staging / "wheelhouse",
        requirement,
        python_version=python_target,
        architecture=architecture_target,
    )


def _stage_guest_boot_files(staging: Path, project: Path, aptl_version: str) -> None:
    """Copy the versioned guest entry point and systemd units into the input set."""

    (staging / "appliance-release.env").write_text(
        f"APTL_APPLIANCE_SCENARIO=techvault\nAPTL_APPLIANCE_VERSION={aptl_version}\n"
    )
    for name in (
        "aptl-appliance-first-boot",
        "aptl-appliance-first-boot.service",
        "aptl-launch.mount",
    ):
        shutil.copyfile(project / "appliance/guest" / name, staging / name)


def stage_canonical_inputs(
    *,
    staging: Path,
    wheelhouse: Path,
    image_archive: Path,
    image_roles: dict[str, str],
    system_packages: Path,
    system_packages_lock: Path,
    target: CanonicalBuildTarget | None = None,
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
    python_target = (target.python_version if target else None) or ".".join(
        platform.python_version().split(".")[:2]
    )
    architecture_target = (
        target.architecture if target else None
    ) or platform.machine()
    if architecture_target not in {"x86_64", "aarch64"}:
        raise ValueError("unsupported canonical input target architecture")
    validate_system_packages(
        system_packages,
        system_packages_lock,
        architecture=architecture_target,
    )
    image_files = archive_files(image_archive)
    images = docker_archive_images(
        image_archive, image_files, architecture=architecture_target
    )
    if set(image_roles.values()) != set(images) or bool(
        HELPER_ROLES - image_roles.keys()
    ):
        raise ValueError("provide exactly the scenario, helper and child image closure")
    staging.mkdir(mode=0o700, parents=True)
    with tempfile.TemporaryDirectory(prefix="aptl-input-build-") as work:
        work = Path(work).resolve(strict=True)
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
            project,
            bundle,
            images,
            image_roles,
            image_archive,
            image_files,
            architecture=architecture_target,
        )
        _build_outputs(project, work)
        shutil.copytree(wheelhouse, staging / "wheelhouse", symlinks=True)
        shutil.copytree(
            system_packages,
            staging / SYSTEM_PACKAGES_DIRECTORY,
            symlinks=True,
        )
        shutil.copyfile(system_packages_lock, staging / SYSTEM_PACKAGES_LOCK)
        _write_wheel_requirements(staging, project, python_target, architecture_target)
        _write_full_profile(project, bundle, matrix, image_roles)
        project_files = _archive_project(project, staging / PROJECT_ARCHIVE)
        shutil.copyfile(image_archive, staging / IMAGE_ARCHIVE)
        _stage_guest_boot_files(staging, project, aptl.__version__)
        assets = _staged_assets(staging, project_files, images)
        inputs = CanonicalInputs(
            schema_version="aptl.canonical-inputs/v1",
            aptl_version=aptl.__version__,
            scenario_pack=bundle.pack_identity,
            python_version=python_target,
            architecture=architecture_target,
            runtime_prerequisites={
                "node": "22.22.1",
                "openssh": "public-key forced-command support",
                "docker": "29.1.3 rootful Linux with nftables",
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
        (staging / INPUTS_RECORD).write_text(inputs.model_dump_json(indent=2) + "\n")
    return validate_canonical_inputs(staging, enforce_runtime_target=False)


def _build_outputs(project: Path, work: Path) -> None:
    """Build locked MCP and frontend packages in the private staging directory."""
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


def _flatten_common_dependencies(project: Path) -> None:
    # npm installs common's dependencies under its real directory, not under
    # the consumers. Preserve that closure when replacing each link: Node then
    # resolves the same versions from the relocated common package.
    """Preserve transitive dependencies when flattening local npm package links."""
    for directory in sorted((project / "mcp").iterdir()):
        linked = directory / "node_modules/aptl-mcp-common"
        if linked.is_symlink():
            target = linked.resolve(strict=True)
            if not target.is_relative_to(project / "mcp"):
                raise ValueError("MCP dependency link escapes package")
            linked.unlink()
            shutil.copytree(target, linked, ignore=shutil.ignore_patterns(".bin"))


def _admit_project_path(name: str) -> None:
    """Reject runtime state and credentials from immutable project inputs."""
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


def _verify_packaged_project(
    staging: Path,
    inputs: CanonicalInputs,
    project: dict[str, str],
    images: dict[str, tuple[str, ...]],
    image_files: dict[str, str],
) -> None:
    """Bind every immutable project asset to the delivered APTL wheel bytes."""

    wheel_path = _canonical_wheel_path(staging, inputs)
    with open_nofollow(wheel_path) as handle, zipfile.ZipFile(handle) as wheel:
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
        _verify_packaged_images(wheel, assets, inputs, staging, images, image_files)
    for name in (
        "aptl-appliance-first-boot",
        "aptl-appliance-first-boot.service",
        "aptl-launch.mount",
    ):
        if hash_file_nofollow(staging / name)[0] != project.get(
            "appliance/guest/" + name
        ):
            raise ValueError("first-boot input differs from the packaged script")
    if hash_file_nofollow(staging / SYSTEM_PACKAGES_LOCK)[0] != project.get(
        "appliance/guest/" + SYSTEM_PACKAGES_LOCK
    ):
        raise ValueError("system package lock differs from the packaged lock")


def _validate_project_runtime(project: dict[str, str]) -> None:
    """Require all built entry points and their locked runtime dependencies."""
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


def _validate_asset_lock(
    staging: Path,
    inputs: CanonicalInputs,
    project: dict[str, str],
    wheels: dict[str, str],
    system_packages: dict[str, str],
    images: dict[str, tuple[str, ...]],
) -> None:
    """Require an exact content and image inventory without duplicate entries."""
    actual = {"project/" + name: digest for name, digest in project.items()}
    actual.update({"wheelhouse/" + name: digest for name, digest in wheels.items()})
    actual.update(
        {"system-packages/" + name: digest for name, digest in system_packages.items()}
    )
    for path in staging.iterdir():
        if path.name not in {
            "wheelhouse",
            SYSTEM_PACKAGES_DIRECTORY,
            INPUTS_RECORD,
        }:
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
    _validate_image_lock(inputs, images)


def _canonical_wheel_path(staging: Path, inputs: CanonicalInputs) -> Path:
    """Select the delivered APTL wheel and require its web dependency extra."""
    from aptl.appliance.payload_content import locked_requirements
    from aptl.appliance.versioning import aptl_wheel_version

    wheels = [
        path
        for path in (staging / "wheelhouse").iterdir()
        if aptl_wheel_version(path.name) is not None
    ]
    if len(wheels) != 1 or aptl_wheel_version(wheels[0].name) != inputs.aptl_version:
        raise ValueError("canonical APTL wheel version differs")
    requirement = locked_requirements(
        (staging / REQUIREMENTS_FILE).read_text(),
        python_version=inputs.python_version,
        architecture=inputs.architecture,
    ).get("aptl-labs")
    if requirement is None or requirement[0].extras != {"web"}:
        raise ValueError("canonical inputs require the complete web dependency closure")
    return wheels[0]


def _staged_assets(
    staging: Path, project_files: dict[str, str], images: dict[str, tuple[str, ...]]
) -> tuple[AssetLockEntry, ...]:
    """Inventory all staged bytes and image identities after the build."""
    assets = []
    for path, digest in sorted(project_files.items()):
        assets.append(_entry(len(assets), "project-file", "project/" + path, digest))
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
    return tuple(assets)


def _validate_image_lock(
    inputs: CanonicalInputs, images: dict[str, tuple[str, ...]]
) -> None:
    """Require exact locked image identities and all apparatus roles."""
    locked_images = {
        asset.source for asset in inputs.asset_lock.assets if asset.kind == "image-id"
    }
    if (
        set(images) != locked_images
        or set(inputs.image_roles.values()) != locked_images
    ):
        raise ValueError("canonical image closure differs from its asset lock")
    if bool(HELPER_ROLES - inputs.image_roles.keys()):
        raise ValueError("canonical helper/child-image identities are missing")


def _verify_packaged_images(
    wheel: zipfile.ZipFile,
    assets: dict[str, str],
    inputs: CanonicalInputs,
    staging: Path,
    images: dict[str, tuple[str, ...]],
    image_files: dict[str, str],
) -> None:
    """Validate the image inventory against assets from the delivered wheel."""
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
            staging / IMAGE_ARCHIVE,
            image_files,
            architecture=inputs.architecture,
        )
        matrix = expected_bundle_matrix(root, AptlConfig(), bundle)
        if set(inputs.image_roles) != {
            *HELPER_ROLES,
            *("scenario." + name for name in matrix.expected_services),
        }:
            raise ValueError("canonical image roles do not match the full scenario")
