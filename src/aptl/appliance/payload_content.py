"""Nested payload content admission; never extracts an unvalidated archive."""

from __future__ import annotations

import gzip
import hashlib
import json
import platform
import re
import stat
import tarfile
import zipfile
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from aptl.utils.deterministic_archive import hash_file_nofollow as _hash_file_nofollow
from aptl.utils.deterministic_archive import open_nofollow

SHA256_PREFIX = "sha256:"
OCI_BLOB_PREFIX = "blobs/"


def hash_file_nofollow(path: Path) -> tuple[str, int]:
    """Use the incumbent streaming reader with the asset-lock hex encoding."""
    digest, size = _hash_file_nofollow(path)
    return digest.removeprefix(SHA256_PREFIX), size


def safe_member(name: str) -> str:
    """Reject ambiguous, escaping, platform-dependent archive names."""
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or "\\" in name
        or "\x00" in name
        or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
    ):
        raise ValueError("unsafe payload archive member")
    return path.as_posix().rstrip("/")


def archive_files(path: Path) -> dict[str, str]:
    """Stream and hash regular members, rejecting links, duplicates and bombs."""
    result = {}
    seen = set()
    implied_dirs = set()
    total = 0
    try:
        with (
            open_nofollow(path) as handle,
            tarfile.open(fileobj=handle, mode="r:*") as archive,
        ):
            for member in archive:
                name = _admit_member(member, seen, implied_dirs, result)
                total += member.size
                if len(seen) > 500_000 or total > 500 * 1024**3 or member.size < 0:
                    raise ValueError("payload archive limits exceeded")
                if member.isfile():
                    result[name] = _archive_member_digest(archive, member)
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("invalid payload archive") from exc
    return result


def read_archive_member(path: Path, name: str, *, limit: int = 4 * 1024**2) -> bytes:
    """Read bounded metadata only after archive_files has admitted its namespace."""
    with open_nofollow(path) as handle, tarfile.open(fileobj=handle) as archive:
        member = archive.getmember(name)
        if not member.isfile() or member.size > limit:
            raise ValueError("invalid payload metadata size")
        return archive.extractfile(member).read()


def locked_requirements(text: str) -> dict[str, tuple[Requirement, set[str]]]:
    """Admit only uv's hash-pinned requirements grammar for this target."""
    result = {}
    for line in text.replace("\\\n", " ").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement, hashes = _locked_requirement(line)
        if requirement.marker and not requirement.marker.evaluate():
            continue
        name = canonicalize_name(requirement.name)
        if name in result:
            raise ValueError("duplicate active Python requirement")
        result[name] = requirement, hashes
    return result


def _wheel_metadata(path: Path) -> tuple[str, Version, Message]:
    """Validate wheel identity, platform and bounded metadata before use."""
    try:
        name, version, _, tags = parse_wheel_filename(path.name)
        if not tags.intersection(sys_tags()):
            raise ValueError("wheel does not match the input validation platform")
        with open_nofollow(path) as handle, zipfile.ZipFile(handle) as archive:
            names = _wheel_names(archive)
            metadata = [
                value for value in names if value.endswith(".dist-info/METADATA")
            ]
            if (
                len(metadata) != 1
                or archive.getinfo(metadata[0]).file_size > 4 * 1024**2
            ):
                raise ValueError("invalid wheel metadata")
            parsed = BytesParser().parsebytes(archive.read(metadata[0]))
        _validate_wheel_identity(parsed, name, version)
        return name, version, parsed
    except (zipfile.BadZipFile, KeyError, TypeError) as exc:
        raise ValueError("invalid wheel archive") from exc


def validate_wheel_closure(wheelhouse: Path, requirements: str) -> dict[str, str]:
    """Verify hashes, platform tags and every transitive metadata dependency."""
    locked = locked_requirements(requirements)
    wheels, hashes = _locked_wheels(wheelhouse, locked)
    extras = {name: set(req.extras) for name, (req, _) in locked.items()}
    changed = True
    while changed:
        changed = _expand_wheel_extras(wheels, extras)
    return hashes


def docker_archive_images(
    path: Path, files: dict[str, str]
) -> dict[str, tuple[str, ...]]:
    """Bind Docker-save image IDs to config bytes and their uncompressed layers."""
    manifests = json.loads(read_archive_member(path, "manifest.json"))
    result = {}
    layer_cache = {}
    if not isinstance(manifests, list) or not manifests:
        raise ValueError("Docker image archive is empty")
    for manifest in manifests:
        config_path = safe_member(manifest["Config"])
        layers = manifest["Layers"]
        config = json.loads(read_archive_member(path, config_path))
        expected = config.get("rootfs", {}).get("diff_ids", [])
        actual = [
            _cached_layer_digest(path, safe_member(layer), layer_cache)
            for layer in layers
        ]
        if not layers or actual != expected:
            raise ValueError("Docker image layers do not match their config identity")
        image_id = SHA256_PREFIX + files[config_path]
        if image_id in result:
            raise ValueError("duplicate Docker image identity")
        result[image_id] = tuple(manifest.get("RepoTags") or ())
    _verify_oci_graph(path, files, result, layer_cache)
    return result


def _layer_digest(path: Path, name: str) -> str:
    """Hash the uncompressed layer stream within a bounded expansion budget."""
    with open_nofollow(path) as handle, tarfile.open(fileobj=handle) as archive:
        raw = archive.extractfile(name)
        prefix = raw.read(2)
        raw.seek(0)
        stream = gzip.GzipFile(fileobj=raw) if prefix == b"\x1f\x8b" else raw
        digest = hashlib.sha256()
        size = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > 100 * 1024**3:
                raise ValueError("expanded image layer exceeds limit")
            digest.update(chunk)
        return SHA256_PREFIX + digest.hexdigest()


def _verify_oci_graph(
    path: Path,
    files: dict[str, str],
    images: dict[str, tuple[str, ...]],
    layer_cache: dict[str, str],
) -> None:
    """Check both Docker and OCI views when modern Docker exports both."""
    for name, digest in files.items():
        if name.startswith("blobs/sha256/") and name != "blobs/sha256/" + digest:
            raise ValueError("OCI blob content identity mismatch")
    if "index.json" not in files:
        return
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    pending = [json.loads(read_archive_member(path, "index.json"))]
    visited = set()
    found = set()
    while pending:
        document = pending.pop()
        if "manifests" in document:
            pending.extend(
                _oci_children(path, files, document["manifests"], architecture, visited)
            )
        elif "config" in document:
            found.update(
                _admit_oci_image(
                    path, files, document, images, layer_cache, architecture
                )
            )
    if found != set(images):
        raise ValueError("OCI and Docker target inventories differ")


def _target_descriptor(descriptor: dict[str, Any], architecture: str | None) -> bool:
    """Select unqualified or native Linux OCI descriptors."""
    target = descriptor.get("platform", {})
    return not target or (
        target.get("os") == "linux" and target.get("architecture") == architecture
    )


def _bounded_manifest_read(path: Path, blob: str, count: int) -> dict[str, Any]:
    """Read one OCI manifest within the graph traversal budget."""
    if count > 4096:
        raise ValueError("OCI manifest graph exceeds limit")
    return json.loads(read_archive_member(path, blob))


def _verify_oci_layers(
    path: Path,
    files: dict[str, str],
    document: dict[str, Any],
    config: dict[str, Any],
    layer_cache: dict[str, str],
) -> None:
    """Verify that OCI layer bytes match their config diff identities."""
    layers = [
        OCI_BLOB_PREFIX + layer["digest"].replace(":", "/")
        for layer in document["layers"]
    ]
    if any(layer not in files for layer in layers):
        raise ValueError("OCI image layer is missing")
    if [
        _cached_layer_digest(path, layer, layer_cache) for layer in layers
    ] != config.get("rootfs", {}).get("diff_ids"):
        raise ValueError("OCI image layers differ from their config identity")


def registry_image_id(path: Path, files: dict[str, str], reference: str) -> str:
    """Resolve a pinned OCI manifest/index to exactly one native image config."""
    digest = reference.rsplit("@", 1)[-1]
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    pending, seen, found = [digest], set(), set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        blob = OCI_BLOB_PREFIX + current.replace(":", "/")
        if blob not in files or len(seen) > 4096:
            raise ValueError("pinned registry image requires its OCI manifest graph")
        document = json.loads(read_archive_member(path, blob))
        if "manifests" in document:
            pending.extend(
                item["digest"]
                for item in document["manifests"]
                if _target_descriptor(item, architecture)
            )
        elif "config" in document:
            config_id = _native_oci_config(path, document, architecture)
            if config_id is not None:
                found.add(config_id)
    if len(found) != 1:
        raise ValueError("registry image does not identify one native config")
    return found.pop()


def _cached_layer_digest(path: Path, name: str, cache: dict[str, str]) -> str:
    """Reuse a verified uncompressed layer digest within one archive."""
    if name not in cache:
        cache[name] = _layer_digest(path, name)
    return cache[name]


def _admit_member(
    member: tarfile.TarInfo,
    seen: set[str],
    implied_dirs: set[str],
    result: dict[str, str],
) -> str:
    """Reject namespace collisions and special entries before reading bytes."""
    name = safe_member(member.name)
    if (
        name in seen
        or (member.isfile() and name in implied_dirs)
        or not (member.isfile() or member.isdir())
    ):
        raise ValueError("duplicate or special payload archive member")
    if any(parent.as_posix() in result for parent in PurePosixPath(name).parents):
        raise ValueError("archive file used as directory")
    seen.add(name)
    implied_dirs.update(parent.as_posix() for parent in PurePosixPath(name).parents)
    return name


def _archive_member_digest(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    """Hash one admitted regular archive member with bounded memory."""
    digest = hashlib.sha256()
    stream = archive.extractfile(member)
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _locked_requirement(line: str) -> tuple[Requirement, set[str]]:
    """Parse one exactly pinned requirement and its complete hash set."""
    pieces = line.split("--hash=sha256:")
    requirement = Requirement(pieces[0].strip())
    hashes = {part.strip() for part in pieces[1:]}
    pins = list(requirement.specifier)
    if (
        requirement.url
        or len(pins) != 1
        or pins[0].operator != "=="
        or "*" in pins[0].version
        or not hashes
        or any(not re.fullmatch("[a-f0-9]{64}", value) for value in hashes)
    ):
        raise ValueError("payload Python requirements must be exactly hash-pinned")
    return requirement, hashes


def _wheel_names(archive: zipfile.ZipFile) -> set[str]:
    """Reject duplicate, linked and oversized wheel content."""
    names = set()
    total = 0
    for member in archive.infolist():
        key = safe_member(member.filename)
        mode = member.external_attr >> 16
        if key in names or stat.S_ISLNK(mode):
            raise ValueError("duplicate or linked wheel member")
        names.add(key)
        total += member.file_size
    if total > 2 * 1024**3:
        raise ValueError("wheel expanded size exceeds limit")
    return names


def _locked_wheels(
    wheelhouse: Path, locked: dict[str, tuple[Requirement, set[str]]]
) -> tuple[dict[str, tuple[Version, Message]], dict[str, str]]:
    """Bind every target wheel to exactly one hash-pinned requirement."""
    wheels = {}
    hashes = {}
    for path in sorted(wheelhouse.iterdir()):
        _require_wheel_file(path)
        name, version, metadata = _wheel_metadata(path)
        digest, _ = hash_file_nofollow(path)
        if (
            name in wheels
            or name not in locked
            or version not in locked[name][0].specifier
            or digest not in locked[name][1]
        ):
            raise ValueError("wheel is not uniquely hash-locked")
        wheels[name] = version, metadata
        hashes[path.name] = digest
    if set(wheels) != set(locked) or "aptl-labs" not in wheels:
        raise ValueError("payload Python wheel closure is incomplete")
    return wheels, hashes


def _expand_wheel_extras(
    wheels: dict[str, tuple[Version, Message]], extras: dict[str, set[str]]
) -> bool:
    """Validate active dependencies and expand requested extras to a fixed point."""
    changed = False
    for name, (_, metadata) in wheels.items():
        for value in metadata.get_all("Requires-Dist", []):
            dependency = Requirement(value)
            if dependency.marker and not any(
                dependency.marker.evaluate({"extra": extra})
                for extra in {"", *extras[name]}
            ):
                continue
            target = canonicalize_name(dependency.name)
            if (
                dependency.url
                or target not in wheels
                or wheels[target][0] not in dependency.specifier
            ):
                raise ValueError("payload Python dependency closure is incomplete")
            added = dependency.extras - extras[target]
            if added:
                extras[target].update(added)
                changed = True
    return changed


def _oci_children(
    path: Path,
    files: dict[str, str],
    descriptors: list[dict[str, Any]],
    architecture: str | None,
    visited: set[str],
) -> list[dict[str, Any]]:
    """Traverse present OCI manifests and reject missing native targets."""
    pending = []
    for descriptor in descriptors:
        blob = OCI_BLOB_PREFIX + descriptor["digest"].replace(":", "/")
        relevant = _target_descriptor(descriptor, architecture)
        if blob not in files:
            if relevant:
                raise ValueError("OCI target manifest is missing")
            continue
        if blob not in visited:
            visited.add(blob)
            pending.append(_bounded_manifest_read(path, blob, len(visited)))
    return pending


def _native_oci_config(
    path: Path, document: dict[str, Any], architecture: str | None
) -> str | None:
    """Resolve a native Linux config from an OCI image manifest."""
    config_id = document["config"]["digest"]
    config = json.loads(
        read_archive_member(path, OCI_BLOB_PREFIX + config_id.replace(":", "/"))
    )
    return (
        config_id
        if config.get("os") == "linux" and config.get("architecture") == architecture
        else None
    )


def _admit_oci_image(
    path: Path,
    files: dict[str, str],
    document: dict[str, Any],
    images: dict[str, tuple[str, ...]],
    layer_cache: dict[str, str],
    architecture: str | None,
) -> set[str]:
    """Require native OCI configs and layers to agree with the Docker inventory."""
    config_id = _native_oci_config(path, document, architecture)
    if config_id is not None:
        if config_id not in images:
            raise ValueError("OCI and Docker image inventories differ")
        config = json.loads(
            read_archive_member(path, OCI_BLOB_PREFIX + config_id.replace(":", "/"))
        )
        _verify_oci_layers(path, files, document, config, layer_cache)
        return {config_id}
    return set()


def _validate_wheel_identity(parsed: Message, name: str, version: Version) -> None:
    """Require metadata identity and interpreter compatibility."""
    if parsed.get("Requires-Python") and Version(
        platform.python_version()
    ) not in SpecifierSet(parsed["Requires-Python"]):
        raise ValueError("wheel requires a different Python version")
    if (
        canonicalize_name(parsed["Name"]) != name
        or Version(parsed["Version"]) != version
    ):
        raise ValueError("wheel filename/metadata mismatch")


def _require_wheel_file(path: Path) -> None:
    """Require a regular wheel input without following a link."""
    if path.is_symlink() or not path.is_file() or path.suffix != ".whl":
        raise ValueError("wheelhouse contains a non-wheel input")
