"""Backend producer for TechVault's generated Cortex service credentials."""

from __future__ import annotations

import re
import secrets
from pathlib import Path

from aptl.core.credentials import (
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
)
from aptl.core.deployment.realization import DeploymentGeneratedArtifactRealization

CORTEX_SERVICE_CREDENTIALS_PROFILE = "techvault:cortex-service-credentials/v1"
CORTEX_SERVICE_CREDENTIALS_ROOT_RELPATH = Path(
    ".aptl/realization/cortex-service-credentials"
)

_EXPECTED_OUTPUTS = {
    "initializer-api-key": "cortex/initializer-api-key",
    "connector-api-key": "cortex/connector-api-key",
}
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43,128}")


def realize_cortex_service_credentials(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
) -> str | None:
    """Create or reuse the exact two distinct secret outputs declared by TechVault."""

    actual = {output.name: output.path for output in artifact.outputs}
    invalid_contract = (
        artifact.provenance != CORTEX_SERVICE_CREDENTIALS_PROFILE
        or artifact.lifecycle != "reuse_valid"
        or actual != _EXPECTED_OUTPUTS
        or any(output.sensitivity != "secret" for output in artifact.outputs)
    )
    if invalid_contract:
        return (
            "Cortex service credential artifact does not match its producer contract."
        )

    try:
        root = _canonical_generated_path(
            scenario_root, CORTEX_SERVICE_CREDENTIALS_ROOT_RELPATH
        )
        _ensure_secure_dir(root)
        existing = {
            name: _read_valid_token(root / relative)
            for name, relative in _EXPECTED_OUTPUTS.items()
        }
        if not all(existing.values()) or len(set(existing.values())) != 2:
            generated = _distinct_tokens()
            for name, relative in _EXPECTED_OUTPUTS.items():
                target = _canonical_generated_path(
                    scenario_root, CORTEX_SERVICE_CREDENTIALS_ROOT_RELPATH / relative
                )
                _ensure_secure_dir(target.parent)
                _atomic_write_secure(target, generated[name] + "\n")
                target.chmod(0o600)
    except (OSError, ValueError):
        return "Cortex service credential generation failed."
    return None


def _read_valid_token(path: Path) -> str | None:
    """Read one generated token only when its bytes match the contract."""

    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token if _TOKEN.fullmatch(token) else None


def _distinct_tokens() -> dict[str, str]:
    """Generate the two distinct service identities required by the pack."""

    initializer = secrets.token_urlsafe(32)
    connector = secrets.token_urlsafe(32)
    while connector == initializer:
        connector = secrets.token_urlsafe(32)
    return {
        "initializer-api-key": initializer,
        "connector-api-key": connector,
    }


__all__ = (
    "CORTEX_SERVICE_CREDENTIALS_PROFILE",
    "CORTEX_SERVICE_CREDENTIALS_ROOT_RELPATH",
    "realize_cortex_service_credentials",
)
