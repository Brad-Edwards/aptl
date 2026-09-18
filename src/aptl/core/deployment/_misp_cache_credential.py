"""Backend producer for the MISP cache credential TechVault leaves open.

The released TechVault pack declares that ``misp-redis`` requires
authentication (``misp-redis-authorization``, ``auth_enabled: true``) and that
its ``misp-cache-client`` principal is ``redacted`` -- a value-free,
backend-selected credential. The pack states the requirement; it does not
choose the bytes or the mechanism. This module is where APTL makes that choice.

The credential reaches both ends of the declared binding without ever entering
host or container argv: the Redis server reads it from an owner-only
configuration file mounted read-only, and MISP receives the same value as
``REDIS_PASSWORD`` through the existing generated-artifact environment
delivery. ``redis-server --requirepass <value>`` would put the secret in the
container's command line and in ``docker inspect`` output, so it is not used.
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path

from aptl.core.credentials import (
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
)
from aptl.core.deployment._compose_stateful_constants import (
    MISP_CACHE_CREDENTIAL_ROOT_RELPATH,
)
from aptl.core.deployment.realization import DeploymentGeneratedArtifactRealization

MISP_CACHE_CREDENTIAL_PROFILE = "techvault:misp-cache-credential/v1"

#: The server reads its credential from this path; only the path, never the
#: credential, appears in the container command.
#: A consumer mount lowers to ``mount_destination / output.path``, so the
#: directory and the output's relative path together have to spell the file the
#: server actually reads. Only the config output is ever selected by a consumer;
#: the password itself is never mounted anywhere.
MISP_CACHE_CONFIG_MOUNT_DESTINATION = "/etc/redis"
MISP_CACHE_CONFIG_RELPATH = "redis.conf"
MISP_CACHE_CONFIG_CONTAINER_PATH = (
    f"{MISP_CACHE_CONFIG_MOUNT_DESTINATION}/{MISP_CACHE_CONFIG_RELPATH}"
)
MISP_CACHE_PASSWORD_OUTPUT = "cache-password"
MISP_CACHE_CONFIG_OUTPUT = "cache-server-config"

_EXPECTED_OUTPUTS = {
    MISP_CACHE_PASSWORD_OUTPUT: "cache-password",
    MISP_CACHE_CONFIG_OUTPUT: MISP_CACHE_CONFIG_RELPATH,
}
# Redis reads its configuration file as whitespace-delimited tokens, so a
# credential containing whitespace or a quote would change the directive rather
# than the value. token_urlsafe emits only [A-Za-z0-9_-].
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43,128}")
_CONFIG_DIRECTIVE = "requirepass"


def realize_misp_cache_credential(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
) -> str | None:
    """Create or reuse the cache credential and the server config that carries it."""

    actual = {output.name: output.path for output in artifact.outputs}
    invalid_contract = (
        artifact.provenance != MISP_CACHE_CREDENTIAL_PROFILE
        or artifact.lifecycle != "reuse_valid"
        or actual != _EXPECTED_OUTPUTS
        or any(output.sensitivity != "secret" for output in artifact.outputs)
    )
    if invalid_contract:
        return "MISP cache credential artifact does not match its producer contract."

    try:
        root = _canonical_generated_path(
            scenario_root, MISP_CACHE_CREDENTIAL_ROOT_RELPATH
        )
        _ensure_secure_dir(root)
        password = _read_valid_token(root / _EXPECTED_OUTPUTS[MISP_CACHE_PASSWORD_OUTPUT])
        if password is None or not _config_matches(
            root / _EXPECTED_OUTPUTS[MISP_CACHE_CONFIG_OUTPUT], password
        ):
            password = secrets.token_urlsafe(32)
            _write_output(
                scenario_root,
                _EXPECTED_OUTPUTS[MISP_CACHE_PASSWORD_OUTPUT],
                password + "\n",
            )
            _write_output(
                scenario_root,
                _EXPECTED_OUTPUTS[MISP_CACHE_CONFIG_OUTPUT],
                f"{_CONFIG_DIRECTIVE} {password}\n",
            )
    except (OSError, ValueError):
        return "MISP cache credential generation failed."
    return None


def _write_output(scenario_root: Path, relative: str, content: str) -> None:
    """Write one owner-only generated output under the contained artifact root."""

    target = _canonical_generated_path(
        scenario_root, MISP_CACHE_CREDENTIAL_ROOT_RELPATH / relative
    )
    _ensure_secure_dir(target.parent)
    _atomic_write_secure(target, content)
    target.chmod(0o600)


def _read_valid_token(path: Path) -> str | None:
    """Read the existing credential only when its bytes match the contract."""

    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token if _TOKEN.fullmatch(token) else None


def _config_matches(path: Path, password: str) -> bool:
    """Return whether the server config still carries exactly this credential.

    Reuse is only safe when both outputs agree. A config that drifted from the
    password file would authenticate the server against one value while MISP
    presented another, which is the failure this check exists to prevent.
    """

    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return content == f"{_CONFIG_DIRECTIVE} {password}\n"


__all__ = (
    "MISP_CACHE_CONFIG_CONTAINER_PATH",
    "MISP_CACHE_CONFIG_MOUNT_DESTINATION",
    "MISP_CACHE_CONFIG_RELPATH",
    "MISP_CACHE_CONFIG_OUTPUT",
    "MISP_CACHE_CREDENTIAL_PROFILE",
    "MISP_CACHE_CREDENTIAL_ROOT_RELPATH",
    "MISP_CACHE_PASSWORD_OUTPUT",
    "realize_misp_cache_credential",
)
