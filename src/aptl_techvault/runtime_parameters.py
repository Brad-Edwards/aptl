"""Per-run values APTL supplies when instantiating the pinned TechVault pack."""

from __future__ import annotations

import secrets
from collections.abc import Mapping

from aptl.backends.scenario_runtime_parameters import EXTENSION_API_VERSION
from aptl.core.scenario_bundle import ScenarioBundle

TECHVAULT_PACK_SET_DIGEST = (
    "sha256:edd3bb6252990aeaf506904767182d5a3ef2b3828a498fe64c897dccaf954934"
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

    The 6.0.1 TechVault release deliberately leaves ten per-host flag values to
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


class TechVaultRuntimeParameterProvider:
    """Bind runtime-owned values only for the exact qualified pack release."""

    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = (_TECHVAULT_PACK_VERSION,)
    supported_pack_set_digests = (TECHVAULT_PACK_SET_DIGEST,)

    @staticmethod
    def resolve(bundle: ScenarioBundle) -> Mapping[str, object] | None:
        return runtime_parameters_for_bundle(bundle)


provider = TechVaultRuntimeParameterProvider()


__all__ = [
    "TECHVAULT_PACK_SET_DIGEST",
    "TechVaultRuntimeParameterProvider",
    "provider",
    "runtime_parameters_for_bundle",
]
