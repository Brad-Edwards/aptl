"""Per-run values APTL supplies when instantiating the pinned TechVault pack."""

from __future__ import annotations

import secrets
from collections.abc import Mapping

from aptl.core.scenario_bundle import ScenarioBundle

TECHVAULT_PACK_SET_DIGEST = (
    "sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b"
)
_TECHVAULT_PACK_VERSION = "0.1.0"
_FLAG_HOSTS = ("victim", "workstation", "webapp", "fileshare", "ad")


def _flag(host: str, level: str) -> str:
    """Return one fresh opaque TechVault host flag value."""

    return f"APTL{{{level}_{host}_{secrets.token_hex(16)}}}"


def runtime_parameters_for_bundle(
    bundle: ScenarioBundle,
) -> Mapping[str, object] | None:
    """Return the exact runtime-owned bindings for a supported pack.

    The 6.1.0 TechVault release deliberately leaves ten per-host flag values to
    the scenario instantiator. Bind only the content-identified release APTL was
    qualified against; another pack or a changed TechVault release remains an
    ordinary required-parameter admission failure.
    """

    identity = getattr(bundle, "pack_identity", None)
    if identity is None or (
        identity.pack_id,
        identity.pack_version,
        identity.set_digest,
    ) != ("techvault", _TECHVAULT_PACK_VERSION, TECHVAULT_PACK_SET_DIGEST):
        return None
    return {
        f"flag_{host}_{level}": _flag(host, level)
        for host in _FLAG_HOSTS
        for level in ("user", "root")
    }


__all__ = ["TECHVAULT_PACK_SET_DIGEST", "runtime_parameters_for_bundle"]
