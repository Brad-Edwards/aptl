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


def prepare_cache_inputs(destination: Path, staging: Path) -> PackIdentity:
    """Verify both source artifacts and emit only the fixed dependency inputs."""
    bundle = env_pack_bundle(staging, "techvault")
    expected = PackIdentity("techvault", "0.1.0", TECHVAULT_PACK_SET_DIGEST)
    if bundle.pack_identity != expected:
        raise ValueError("unsupported cache input pack identity")
    files: dict[str, bytes] = {}
    for identity in ("techvault-red-mcp-sources", "techvault-blue-mcp-sources"):
        resolved = resolve_pack_artifact(bundle.root, identity)
        with tarfile.open(fileobj=io.BytesIO(resolved.data)) as archive:
            for member in archive:
                if member.name not in _LOCKFILES:
                    continue
                if not member.isfile() or member.size > 8 * 1024 * 1024:
                    raise ValueError("invalid cache lockfile")
                reader = archive.extractfile(member)
                assert reader is not None
                with reader:
                    payload = reader.read()
                if member.name in files and files[member.name] != payload:
                    raise ValueError("conflicting cache lockfiles")
                files[member.name] = payload
    if files.keys() != _LOCKFILES:
        raise ValueError("incomplete cache lockfiles")
    destination.mkdir(parents=True, exist_ok=False)
    for name, payload in files.items():
        if name.endswith("/package.json"):
            # These private manifests only populate a dependency cache. npm 10
            # can run local dependency prepare scripts despite --ignore-scripts.
            # Exclude executable hooks from this derivative, never from the
            # verified pack or the runtime artifacts later admitted from it.
            manifest = json.loads(payload)
            manifest.pop("scripts", None)
            payload = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        create_exclusive_nofollow(destination, name, payload)
    return expected


if __name__ == "__main__":
    identity = prepare_cache_inputs(Path(sys.argv[1]), Path(sys.argv[2]))
    print(json.dumps(asdict(identity), sort_keys=True))
