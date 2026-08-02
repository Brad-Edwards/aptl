"""Realize an ``ssh_key_bundle`` generated artifact (#875).

The scenario declares SSH key material as a generated artifact rather than
shipping it as content, so APTL *generates* real keypairs and authorized-key
projections at standup — nothing is pre-baked. Each declared output lands at its
relative path under an owner-only staging root; the mount model then binds only a
consumer's ``selected_outputs`` (never a ``producer_private`` output such as the
control-plane key), so the private control-plane key is generated but never
reaches any node.

Dispatch is on the artifact's ``provenance`` — the ``(generator kind, producer
profile)`` seam from the issue #875 preflight. The one profile implemented is
``techvault:ssh-access-profile/v1``, whose key relationships reproduce the proven
TechVault topology (``aptl.core.ssh``): a control-plane key, a kali pivot key, a
workstation pivot key, and a dev-user keypair, with each authorized-keys file
authorizing exactly the public halves that make its declared access path work.
"""

from __future__ import annotations

from pathlib import Path

from aptl.core.deployment.realization import DeploymentGeneratedArtifactRealization
from aptl.core.ssh import _run_ssh_keygen, _set_public_key_mode, _with_trailing_newline

SSH_ACCESS_PROFILE_V1 = "techvault:ssh-access-profile/v1"

# Output names whose declared output is the private half of a keypair APTL
# generates. ``ssh-keygen`` writes the matching ``.pub`` beside it, which the
# authorized-keys projections below consume; a ``.pub`` is only a declared output
# when the profile names one (the dev-user public key).
_KEYPAIR_OUTPUTS = (
    "operator-private-key",
    "workstation-dev-private-key",
    "workstation-pivot-private-key",
    "kali-pivot-private-key",
)

# Each authorized-keys output authorizes the public halves of these keypairs.
# Reproduces aptl.core.ssh: a target authorizes the control-plane, kali-pivot and
# workstation-pivot keys; kali authorizes only the control-plane key.
_AUTHORIZED_KEYS = {
    "target-authorized-keys": (
        "operator-private-key",
        "kali-pivot-private-key",
        "workstation-pivot-private-key",
    ),
    "kali-authorized-keys": ("operator-private-key",),
}

_KEYGEN_COMMENT = {
    "operator-private-key": "aptl-control-plane",
    "workstation-dev-private-key": "aptl-workstation-dev",
    "workstation-pivot-private-key": "aptl-workstation-pivot",
    "kali-pivot-private-key": "aptl-kali-pivot",
}


def realize_ssh_key_bundle(
    artifact: DeploymentGeneratedArtifactRealization, staging_root: Path
) -> str | None:
    """Generate the SSH key bundle under ``staging_root``; return an error or None.

    ``staging_root`` is the artifact's owner-only source directory (under the
    scenario bundle root). Every declared output must exist afterwards or the run
    fails closed.
    """

    if artifact.provenance != SSH_ACCESS_PROFILE_V1:
        return (
            f"Unsupported ssh_key_bundle producer profile {artifact.provenance!r}."
        )
    by_name = {output.name: output for output in artifact.outputs}
    staging_root.mkdir(parents=True, exist_ok=True)

    error = _generate_keypairs(by_name, staging_root)
    if error is not None:
        return error
    error = _write_authorized_keys(by_name, staging_root)
    if error is not None:
        return error

    missing = [
        output.path
        for output in artifact.outputs
        if not (staging_root / output.path).is_file()
    ]
    if missing:
        return f"ssh_key_bundle {artifact.name} is missing declared output(s): {missing}."
    return None


def _generate_keypairs(by_name, staging_root: Path) -> str | None:
    """Generate each declared keypair's private half (and its ``.pub``)."""

    for name in _KEYPAIR_OUTPUTS:
        output = by_name.get(name)
        if output is None:
            continue
        private_key = staging_root / output.path
        private_key.parent.mkdir(parents=True, exist_ok=True)
        error = _run_ssh_keygen(
            private_key, _KEYGEN_COMMENT.get(name, "aptl-ssh"), f"ssh-keygen ({name})"
        )
        if error:
            return error
    return None


def _write_authorized_keys(by_name, staging_root: Path) -> str | None:
    """Compose each declared authorized_keys file from the authorized public keys."""

    for name, authorized in _AUTHORIZED_KEYS.items():
        output = by_name.get(name)
        if output is None:
            continue
        lines = []
        for keypair_name in authorized:
            keypair = by_name.get(keypair_name)
            if keypair is None:
                continue
            public_key = staging_root / f"{keypair.path}.pub"
            if not public_key.is_file():
                return f"missing public key for {keypair_name} while composing {name}."
            lines.append(_with_trailing_newline(public_key.read_text()))
        target = staging_root / output.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(lines))
        mode_error = _set_public_key_mode(target)
        if mode_error:
            return mode_error
    return None
