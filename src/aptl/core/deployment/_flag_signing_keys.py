"""Realize the ``techvault:flag-signing-profile/v2`` flag-signing keys (#875).

The scenario declares per-node CTF flag-signing keys as a backend-produced
``rendered_config`` generated artifact rather than shipping key bytes in the
pack. APTL generates a single producer-private seed and derives one key per
consuming node from it, so:

* each node receives only its own key (bind-mounted at
  ``/run/techvault/flag-signing/<node>.key``), which the per-node
  ``aptl-flaggen`` oneshot reads to HMAC-sign ``aptl:v2`` flag tokens; and
* the producer retains the seed (a ``producer_private`` output, never mounted
  into a node), from which the scoring collector can re-derive any node's key to
  verify the tokens it reads back.

Dispatch is on the artifact's ``provenance`` — the ``(generator kind, producer
profile)`` seam. This module implements ``techvault:flag-signing-profile/v2``;
the key derivation is ``HMAC-SHA256(seed, node)`` so it is reproducible from the
seed alone.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path

from aptl.core.deployment.realization import DeploymentGeneratedArtifactRealization

FLAG_SIGNING_PROFILE_V2 = "techvault:flag-signing-profile/v2"

_SEED_OUTPUT = "signing-seed"


def realize_flag_signing_keys(
    artifact: DeploymentGeneratedArtifactRealization,
    staging_root: Path,
) -> str | None:
    """Generate the flag-signing seed and per-node keys under ``staging_root``.

    Returns an error string on failure, or ``None`` on success. Every declared
    output must exist afterwards or the run fails closed.
    """

    if artifact.provenance != FLAG_SIGNING_PROFILE_V2:
        return f"Unsupported flag-signing producer profile {artifact.provenance!r}."

    staging_root.mkdir(parents=True, exist_ok=True)
    seed_output = next(
        (output for output in artifact.outputs if output.name == _SEED_OUTPUT), None
    )
    if seed_output is None:
        return f"flag-signing artifact {artifact.name} declares no {_SEED_OUTPUT!r} output."

    seed = _load_or_create_seed(staging_root / seed_output.path)

    for output in artifact.outputs:
        if output.name == _SEED_OUTPUT:
            continue
        # The node whose key this is: the output path's stem (victim.key ->
        # victim). Its aptl-flaggen unit mounts and reads exactly this file.
        node = Path(output.path).stem
        key = hmac.new(seed, node.encode("utf-8"), hashlib.sha256).hexdigest()
        destination = staging_root / output.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(key + "\n", encoding="utf-8")
        destination.chmod(0o600)

    missing = [
        output.path
        for output in artifact.outputs
        if not (staging_root / output.path).is_file()
    ]
    if missing:
        return f"flag-signing keys {artifact.name} missing declared output(s): {missing}."
    return None


def _load_or_create_seed(seed_path: Path) -> bytes:
    """Return the persistent signing seed, creating it once if absent.

    Reusing an existing seed keeps a node's derived key stable across restarts so
    tokens signed before a restart still verify; a fresh lab mints a new seed.
    """

    if seed_path.is_file():
        existing = seed_path.read_text(encoding="utf-8").strip()
        if existing:
            return bytes.fromhex(existing)
    seed = secrets.token_bytes(32)
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_text(seed.hex() + "\n", encoding="utf-8")
    seed_path.chmod(0o600)
    return seed
