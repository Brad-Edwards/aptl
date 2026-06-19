"""SSH key generation and distribution.

Generates ed25519 SSH key pairs for lab container access and copies
public keys to the container keys directory for authorized_keys setup.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from aptl.utils.logging import get_logger

log = get_logger("ssh")

_KEY_NAME = "aptl_lab_key"
_PIVOT_KEY_NAME = "kali_pivot_key"


@dataclass
class SSHKeyResult(object):
    """Result of SSH key generation."""

    success: bool
    generated: bool
    key_path: Optional[Path] = None
    error: str = ""


def ensure_ssh_keys(keys_dir: Path, host_ssh_dir: Path) -> SSHKeyResult:
    """Ensure SSH keys exist for lab access.

    If keys already exist in host_ssh_dir, they are reused.
    Otherwise, new ed25519 keys are generated via ssh-keygen.
    The public key is always copied to keys_dir for container consumption.

    Args:
        keys_dir: Directory where public keys are placed for containers
                  (e.g., containers/keys/).
        host_ssh_dir: Host SSH directory where the key pair lives
                      (e.g., ~/.ssh/).

    Returns:
        SSHKeyResult indicating success, whether keys were generated,
        and the path to the private key.
    """
    # Ensure directories exist
    keys_dir.mkdir(parents=True, exist_ok=True)
    host_ssh_dir.mkdir(parents=True, exist_ok=True)

    private_key = host_ssh_dir / _KEY_NAME
    public_key = host_ssh_dir / f"{_KEY_NAME}.pub"

    generated = False

    if not private_key.exists():
        log.info("Generating new SSH key pair at %s", private_key)
        result = subprocess.run(
            [
                "ssh-keygen",
                "-t", "ed25519",
                "-f", str(private_key),
                "-N", "",
                "-C", "aptl-local-lab",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            log.error("ssh-keygen failed: %s", error_msg)
            return SSHKeyResult(
                success=False,
                generated=False,
                error=error_msg,
            )

        generated = True
        log.info("SSH key pair generated successfully")
    else:
        log.debug("SSH key already exists at %s", private_key)

    # Verify public key exists before proceeding
    if not public_key.exists():
        log.error("Public key not found at %s after keygen", public_key)
        return SSHKeyResult(
            success=False,
            generated=generated,
            error=f"Public key not found at {public_key}",
        )

    # Set permissions on key files
    os.chmod(private_key, 0o600)
    os.chmod(public_key, 0o644)

    # Copy public key to keys_dir for container authorized_keys
    pub_content = public_key.read_text()
    (keys_dir / f"{_KEY_NAME}.pub").write_text(pub_content)
    (keys_dir / "authorized_keys").write_text(pub_content)

    log.debug("Public key distributed to %s", keys_dir)

    return SSHKeyResult(
        success=True,
        generated=generated,
        key_path=private_key,
    )


def ensure_pivot_key(pivot_dir: Path) -> SSHKeyResult:
    """Ensure the kali pivot keypair exists.

    The pivot key is *scenario content*, distinct from the operator/MCP
    control-plane key (``aptl_lab_key``). kali uses it to SSH into the lab
    targets — that is the deliberate in-scenario attack path — so its private
    half is mounted into kali only and its public half is authorized on the
    targets. Because it never leaves the scenario (the control plane uses
    ``aptl_lab_key``, not this key), it is captured unredacted in inventory
    evidence like any other scenario fixture (SEC #417).

    Both halves live in ``pivot_dir`` (gitignored, e.g. ``config/lab-ssh/``)
    and are generated once at lab standup.

    Args:
        pivot_dir: Directory that holds the pivot keypair, bind-mounted into
                   the lab containers.

    Returns:
        SSHKeyResult indicating success, whether the key was generated, and
        the path to the private key.
    """
    pivot_dir.mkdir(parents=True, exist_ok=True)

    private_key = pivot_dir / _PIVOT_KEY_NAME
    public_key = pivot_dir / f"{_PIVOT_KEY_NAME}.pub"

    generated = False

    if not private_key.exists():
        log.info("Generating kali pivot key pair at %s", private_key)
        result = subprocess.run(
            [
                "ssh-keygen",
                "-t", "ed25519",
                "-f", str(private_key),
                "-N", "",
                "-C", "aptl-kali-pivot",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            log.error("ssh-keygen (pivot) failed: %s", error_msg)
            return SSHKeyResult(
                success=False,
                generated=False,
                error=error_msg,
            )

        generated = True
        log.info("Kali pivot key pair generated successfully")
    else:
        log.debug("Kali pivot key already exists at %s", private_key)

    if not public_key.exists():
        log.error("Pivot public key not found at %s after keygen", public_key)
        return SSHKeyResult(
            success=False,
            generated=generated,
            error=f"Pivot public key not found at {public_key}",
        )

    # Lock the private half to owner-only. The public half keeps ssh-keygen's
    # default world-readable mode (it is a public key, bound read-only into the
    # targets), so it is left as generated rather than re-chmod'd here.
    os.chmod(private_key, 0o600)

    return SSHKeyResult(
        success=True,
        generated=generated,
        key_path=private_key,
    )
