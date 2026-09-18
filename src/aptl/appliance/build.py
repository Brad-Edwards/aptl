"""Fixed-argument offline construction of an immutable QEMU golden image."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aptl.appliance.models import GoldenImageInventory
from aptl.appliance.release_models import ApplianceLaunchDescriptor
from aptl.utils.strict_json import loads_strict

_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"


class ApplianceBuildError(RuntimeError):
    """A golden image could not be built without weakening its contract."""


def _safe_relative_path(value: str) -> str:
    """Validate a contained, normalized POSIX request path."""

    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "//" in value
        or value.startswith("./")
        or path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("build path must be a safe relative POSIX path")
    return value


class GoldenImageBuildRequest(BaseModel):
    """Checksum-pinned inputs for one offline, replacement-only image build."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.golden-image-build/v1"]
    base_image_path: str
    base_image_digest: str = Field(pattern=_SHA256_PATTERN)
    offline_payload_path: str
    offline_payload_digest: str = Field(pattern=_SHA256_PATTERN)
    provisioner_path: str
    provisioner_digest: str = Field(pattern=_SHA256_PATTERN)
    scanner_path: str
    scanner_digest: str = Field(pattern=_SHA256_PATTERN)
    output_image_path: str
    inventory_output_path: str
    virtual_size_bytes: int = Field(ge=100 * 1024**3)

    @field_validator(
        "base_image_path",
        "offline_payload_path",
        "provisioner_path",
        "scanner_path",
        "output_image_path",
        "inventory_output_path",
    )
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _safe_relative_path(value)

    @field_validator("offline_payload_path")
    @classmethod
    def validate_offline_payload_name(cls, value: str) -> str:
        if PurePosixPath(value).name != "offline-payload.tar":
            raise ValueError("offline payload path must end in offline-payload.tar")
        return value


class OverlayCreateRequest(BaseModel):
    """Content-pinned local-KVM disposable-overlay request."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.overlay-create/v1"]
    golden_image_path: str
    golden_image_digest: str = Field(pattern=_SHA256_PATTERN)
    launch_descriptor_path: str
    launch_descriptor_digest: str = Field(pattern=_SHA256_PATTERN)
    overlay_path: str

    @field_validator("golden_image_path", "launch_descriptor_path", "overlay_path")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _safe_relative_path(value)


@dataclass(frozen=True)
class GoldenImageBuildResult:
    """Safe identity of the finalized immutable candidate."""

    output_path: Path
    inventory_path: Path
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class OverlayCreateResult:
    """Safe identity of one newly created mutable overlay."""

    overlay_path: Path
    golden_image_digest: str


def prepare_golden_image_request(
    build_root: Path,
    *,
    base_image_path: str,
    offline_payload_path: str,
    provisioner_path: str,
    scanner_path: str,
    output_image_path: str,
    inventory_output_path: str,
    virtual_size_bytes: int,
    request_path: str,
) -> GoldenImageBuildRequest:
    """Derive one checksum-pinned build request from already staged inputs."""

    root = build_root.resolve(strict=True)
    values = {
        name: _safe_relative_path(value)
        for name, value in {
            "base_image_path": base_image_path,
            "offline_payload_path": offline_payload_path,
            "provisioner_path": provisioner_path,
            "scanner_path": scanner_path,
            "output_image_path": output_image_path,
            "inventory_output_path": inventory_output_path,
            "request_path": request_path,
        }.items()
    }
    output = _output_path(root, values.pop("request_path"))
    if output.exists() or output.is_symlink():
        raise ApplianceBuildError("golden image request already exists")

    def digest(relative: str) -> str:
        """Return the no-follow identity of a contained build input."""

        candidate = root / relative
        parent = candidate.parent.resolve(strict=True)
        if not parent.is_relative_to(root):
            raise ApplianceBuildError("golden image request input escapes build root")
        return _file_identity(parent / candidate.name, nofollow=True)[0]

    request = GoldenImageBuildRequest(
        schema_version="aptl.golden-image-build/v1",
        base_image_path=values["base_image_path"],
        base_image_digest=digest(values["base_image_path"]),
        offline_payload_path=values["offline_payload_path"],
        offline_payload_digest=digest(values["offline_payload_path"]),
        provisioner_path=values["provisioner_path"],
        provisioner_digest=digest(values["provisioner_path"]),
        scanner_path=values["scanner_path"],
        scanner_digest=digest(values["scanner_path"]),
        output_image_path=values["output_image_path"],
        inventory_output_path=values["inventory_output_path"],
        virtual_size_bytes=virtual_size_bytes,
    )
    payload = rfc8785.dumps(request.model_dump(mode="json"))
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return request


class CommandRunner(Protocol):
    """Injectable fixed-argv subprocess boundary."""

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]: ...


def _run_command(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one fixed-argument image tool command with bounded capture."""

    return subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        timeout=3600,
    )


def _require_standalone_qcow(path: Path, runner: CommandRunner) -> None:
    """Reject qcow2 images with external backing or data-file dependencies."""

    try:
        result = runner(["qemu-img", "info", "--output=json", str(path)])
    except (
        ApplianceBuildError,
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        raise ApplianceBuildError("qcow2 metadata could not be inspected") from exc
    if len(result.stdout) > 1024 * 1024:
        raise ApplianceBuildError("qcow2 metadata exceeds the admission limit")
    try:
        document = loads_strict(result.stdout)
    except (TypeError, ValueError) as exc:
        raise ApplianceBuildError("qcow2 metadata is invalid") from exc
    external_fields = {
        "backing-filename",
        "full-backing-filename",
        "backing-filename-format",
        "data-file",
    }
    if (
        not isinstance(document, dict)
        or document.get("format") != "qcow2"
        or external_fields & document.keys()
    ):
        raise ApplianceBuildError("qcow2 image is not standalone")


def _verified_input(
    root: Path,
    relative_path: str,
    expected_digest: str,
    *,
    label: str,
) -> Path:
    """Resolve and digest-check a regular contained build input."""

    try:
        path = root / relative_path
        parent = path.parent.resolve(strict=True)
        if not parent.is_relative_to(root):
            raise ValueError("input escapes build root")
        resolved = parent / path.name
        actual, _ = _file_identity(resolved, nofollow=True)
    except (OSError, ValueError) as exc:
        raise ApplianceBuildError(f"unsafe {label} path") from exc
    if actual != expected_digest:
        raise ApplianceBuildError(f"{label} digest does not match")
    return resolved


def _output_path(root: Path, relative_path: str) -> Path:
    """Resolve an output beneath a create-once owner-only parent."""

    output = root / relative_path
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise ApplianceBuildError("golden image output parent is unsafe") from exc
    if not resolved_parent.is_relative_to(root):
        raise ApplianceBuildError("golden image output escapes the build root")
    return resolved_parent / output.name


def _build_commands(
    base: Path,
    payload: Path,
    provisioner: Path,
    scanner: Path,
    candidate: Path,
    virtual_size_bytes: int,
) -> tuple[list[str], ...]:
    """Return the complete fixed-argument offline image build sequence."""

    return (
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            str(candidate),
            str(virtual_size_bytes),
        ],
        [
            "virt-resize",
            "--expand",
            "/dev/sda1",
            str(base),
            str(candidate),
        ],
        [
            "virt-customize",
            "-a",
            str(candidate),
            "--no-network",
            "--mkdir",
            "/opt/aptl-stage",
            "--copy-in",
            f"{payload}:/opt/aptl-stage",
            "--run",
            str(provisioner),
        ],
        [
            "virt-sysprep",
            "-a",
            str(candidate),
            "--operations",
            "machine-id,ssh-hostkeys,logfiles,tmp-files,package-manager-cache",
            "--delete",
            "/var/lib/docker/*",
            "--delete",
            "/var/lib/aptl/*",
            "--delete",
            "/opt/aptl/project/.aptl/*",
            "--delete",
            "/var/lib/cloud/instance",
            "--delete",
            "/var/lib/cloud/instances/*",
            "--delete",
            "/var/lib/cloud/seed/*",
        ],
        [
            "virt-customize",
            "-a",
            str(candidate),
            "--no-network",
            "--run",
            str(scanner),
        ],
        ["qemu-img", "check", "-q", str(candidate)],
    )


def _file_identity(path: Path, *, nofollow: bool = False) -> tuple[str, int]:
    """Stream one regular file into its SHA-256 identity and size."""

    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | os.O_CLOEXEC
    if nofollow and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError("appliance input is not a regular file")
    with os.fdopen(fd, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return f"sha256:{digest.hexdigest()}", size


def _build_inputs(
    root: Path,
    request: GoldenImageBuildRequest,
) -> tuple[Path, Path, Path, Path]:
    """Resolve and verify every checksum-pinned build input."""

    return (
        _verified_input(
            root,
            request.base_image_path,
            request.base_image_digest,
            label="base image",
        ),
        _verified_input(
            root,
            request.offline_payload_path,
            request.offline_payload_digest,
            label="offline payload",
        ),
        _verified_input(
            root,
            request.provisioner_path,
            request.provisioner_digest,
            label="provisioner",
        ),
        _verified_input(
            root,
            request.scanner_path,
            request.scanner_digest,
            label="golden image scanner",
        ),
    )


def _remove_candidates(paths: tuple[Path, ...]) -> None:
    """Best-effort remove build candidates without masking the build result."""

    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def build_golden_image(
    build_root: Path,
    request: GoldenImageBuildRequest,
    *,
    runner: CommandRunner = _run_command,
) -> GoldenImageBuildResult:
    """Create a new read-only image; never edit or replace an existing release."""

    root = build_root.resolve()
    base, payload, provisioner, scanner = _build_inputs(root, request)
    output = _output_path(root, request.output_image_path)
    inventory_output = _output_path(root, request.inventory_output_path)
    if (
        output.exists()
        or output.is_symlink()
        or inventory_output.exists()
        or inventory_output.is_symlink()
    ):
        raise ApplianceBuildError("golden image output already exists")
    candidate = output.with_name(f"{output.name}.candidate-{secrets.token_hex(8)}")
    inventory_candidate = inventory_output.with_name(
        f"{inventory_output.name}.candidate-{secrets.token_hex(8)}"
    )
    inventory_linked = False
    try:
        _require_standalone_qcow(base, runner)
        for argv in _build_commands(
            base,
            payload,
            provisioner,
            scanner,
            candidate,
            request.virtual_size_bytes,
        ):
            runner(argv)
        if not candidate.is_file() or candidate.is_symlink():
            raise ApplianceBuildError("golden image candidate was not produced")
        _require_standalone_qcow(candidate, runner)
        inventory = GoldenImageInventory(
            schema_version="aptl.golden-inventory/v1",
            scan_complete=True,
            populated_sensitive_paths=(),
            writable_runtime_paths=(),
        )
        inventory_candidate.write_bytes(
            rfc8785.dumps(inventory.model_dump(mode="json"))
        )
        digest, size = _file_identity(candidate, nofollow=True)
        candidate.chmod(0o444)
        inventory_candidate.chmod(0o444)
        os.link(inventory_candidate, inventory_output, follow_symlinks=False)
        inventory_linked = True
        os.link(candidate, output, follow_symlinks=False)
        return GoldenImageBuildResult(
            output_path=output,
            inventory_path=inventory_output,
            sha256=digest,
            size_bytes=size,
        )
    except (
        ApplianceBuildError,
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        if inventory_linked and not output.exists():
            try:
                inventory_output.unlink()
            except OSError:
                pass
        raise ApplianceBuildError("golden image build failed") from exc
    finally:
        _remove_candidates((candidate, inventory_candidate))


def create_disposable_overlay(
    appliance_root: Path,
    request: OverlayCreateRequest,
    *,
    runner: CommandRunner = _run_command,
) -> OverlayCreateResult:
    """Create one qcow2 overlay without opening the golden base for writing."""

    root = appliance_root.resolve()
    golden = _verified_input(
        root,
        request.golden_image_path,
        request.golden_image_digest,
        label="golden image",
    )
    if golden.stat(follow_symlinks=False).st_mode & 0o222:
        raise ApplianceBuildError("golden image must be read-only")
    _require_standalone_qcow(golden, runner)
    launch_path = _verified_input(
        root,
        request.launch_descriptor_path,
        request.launch_descriptor_digest,
        label="launch descriptor",
    )
    try:
        launch = ApplianceLaunchDescriptor.model_validate_json(launch_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ApplianceBuildError("launch descriptor is invalid") from exc
    if launch.golden_image_digest != request.golden_image_digest:
        raise ApplianceBuildError("launch descriptor does not match the golden image")
    overlay = _output_path(root, request.overlay_path)
    if overlay.exists() or overlay.is_symlink():
        raise ApplianceBuildError("disposable overlay output already exists")
    candidate = overlay.with_name(f"{overlay.name}.candidate-{secrets.token_hex(8)}")
    try:
        runner(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(golden),
                str(candidate),
            ]
        )
        runner(["qemu-img", "check", "-q", str(candidate)])
        if not candidate.is_file() or candidate.is_symlink():
            raise ApplianceBuildError("disposable overlay candidate was not produced")
        candidate.chmod(0o600)
        os.link(candidate, overlay, follow_symlinks=False)
        return OverlayCreateResult(
            overlay_path=overlay,
            golden_image_digest=request.golden_image_digest,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ApplianceBuildError("disposable overlay creation failed") from exc
    finally:
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass
