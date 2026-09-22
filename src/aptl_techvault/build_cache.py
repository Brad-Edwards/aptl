"""Verified TechVault lockfiles for APTL's offline Node dependency cache.

This backend build integration supplies dependency bytes only. Runtime source
still arrives through admitted pack artifacts, never from this image cache.
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
from dataclasses import asdict
from pathlib import Path

from raes_env_packs import resolve_pack_artifact

from aptl.core.scenario_bundle import PackIdentity, env_pack_bundle
from aptl.utils.pathsafe import create_exclusive_nofollow
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST

_PROJECTS = (
    "aptl-mcp-common",
    "mcp-casemgmt",
    "mcp-indexer",
    "mcp-network",
    "mcp-red",
    "mcp-reverse",
    "mcp-soar",
    "mcp-threatintel",
    "mcp-wazuh",
)
_LOCKFILES = frozenset(
    f"{project}/{name}"
    for project in _PROJECTS
    for name in ("package.json", "package-lock.json")
)


# The node22 backend image build is this integration's only caller, and it
# always uses these locations. Fixing them here keeps the output root out of
# caller control entirely instead of trusting whatever path argv supplies.
BUILD_CACHE_DESTINATION = Path("/opt/aptl/npm-source")
BUILD_CACHE_STAGING = Path("/opt/aptl/npm-cache-pack")


def prepare_cache_inputs(destination: Path, staging: Path) -> PackIdentity:
    """Verify both source artifacts and emit only the fixed dependency inputs."""
    bundle = env_pack_bundle(staging, "techvault")
    expected = PackIdentity("techvault", "0.1.0", TECHVAULT_PACK_SET_DIGEST)
    if bundle.pack_identity != expected:
        raise ValueError("unsupported cache input pack identity")
    files = _verified_lockfiles(bundle.root)
    # Every appended name is a member of the fixed _LOCKFILES allowlist and is
    # written no-follow under the fixed build destination.
    destination.mkdir(parents=True, exist_ok=False)
    for name, payload in files.items():
        if name.endswith("/package.json"):
            payload = _dependency_only_manifest(payload)
        create_exclusive_nofollow(destination, name, payload)
    return expected


def _verified_lockfiles(pack_root: Path) -> dict[str, bytes]:
    """Read exactly the allowlisted lockfiles out of both verified source artifacts."""
    files: dict[str, bytes] = {}
    for identity in ("techvault-red-mcp-sources", "techvault-blue-mcp-sources"):
        resolved = resolve_pack_artifact(pack_root, identity)
        with tarfile.open(fileobj=io.BytesIO(resolved.data)) as archive:
            for member in archive:
                if member.name in _LOCKFILES:
                    _record_lockfile(
                        files, member.name, _read_lockfile(archive, member)
                    )
    if files.keys() != _LOCKFILES:
        raise ValueError("incomplete cache lockfiles")
    return files


def _read_lockfile(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    """Return one lockfile member's bytes, refusing non-files and oversized entries."""
    if not member.isfile() or member.size > 8 * 1024 * 1024:
        raise ValueError("invalid cache lockfile")
    reader = archive.extractfile(member)
    assert reader is not None
    with reader:
        return reader.read()


def _record_lockfile(files: dict[str, bytes], name: str, payload: bytes) -> None:
    """Record a lockfile, refusing a second artifact that disagrees on its bytes."""
    if name in files and files[name] != payload:
        raise ValueError("conflicting cache lockfiles")
    files[name] = payload


def _dependency_only_manifest(payload: bytes) -> bytes:
    """Drop lifecycle hooks from a manifest used only to populate the npm cache.

    npm 10 can run local dependency prepare scripts despite --ignore-scripts.
    Exclude executable hooks from this derivative, never from the verified pack
    or the runtime artifacts later admitted from it.
    """
    manifest = json.loads(payload)
    manifest.pop("scripts", None)
    return (json.dumps(manifest, sort_keys=True) + "\n").encode()


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("usage: python -m aptl_techvault.build_cache")
    identity = prepare_cache_inputs(BUILD_CACHE_DESTINATION, BUILD_CACHE_STAGING)
    print(json.dumps(asdict(identity), sort_keys=True))
