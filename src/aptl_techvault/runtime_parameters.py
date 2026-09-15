"""Per-run values APTL supplies when instantiating the pinned TechVault pack."""

from __future__ import annotations

import secrets
from collections.abc import Mapping

from aptl.core.scenario_bundle import ScenarioBundle

TECHVAULT_PACK_SET_DIGEST = (
    "sha256:6300b3d539ab9c1e2287b9852e5408e1811516b818a7acf015f045cb3c9c5b89"
)
_TECHVAULT_PACK_VERSION = "0.1.0"


def _flag(level: str) -> str:
    """Return one fresh opaque TechVault AD flag value."""

    return f"APTL{{{level}_ad_{secrets.token_hex(16)}}}"


def runtime_parameters_for_bundle(
    bundle: ScenarioBundle,
) -> Mapping[str, object] | None:
    """Return the exact runtime-owned bindings for a supported pack.

    The 6.0 TechVault release deliberately leaves its two AD flag values to
    the scenario instantiator.  Bind only the content-identified release APTL
    was qualified against; another pack or a changed TechVault release remains
    an ordinary required-parameter admission failure.
    """

    identity = getattr(bundle, "pack_identity", None)
    if identity is None or (
        identity.pack_id,
        identity.pack_version,
        identity.set_digest,
    ) != ("techvault", _TECHVAULT_PACK_VERSION, TECHVAULT_PACK_SET_DIGEST):
        return None
    return {
        "flag_ad_user": _flag("user"),
        "flag_ad_root": _flag("root"),
    }


__all__ = ["TECHVAULT_PACK_SET_DIGEST", "runtime_parameters_for_bundle"]
