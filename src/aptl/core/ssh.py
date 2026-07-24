"""SSH key generation and distribution.

Generates ed25519 SSH key pairs for lab container access and copies
public keys to the container keys directory for authorized_keys setup.
"""

import getpass
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from aptl.core import hostenv
from aptl.utils.logging import get_logger

log = get_logger("ssh")

_KEY_NAME = "aptl_lab_key"
_PIVOT_KEY_NAME = "kali_pivot_key"
_WORKSTATION_PIVOT_KEY_NAME = "workstation_pivot_key"


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

    generated, error_msg = _ensure_keypair(
        private_key=private_key,
        comment="aptl-local-lab",
        label="ssh-keygen",
    )
    if error_msg:
        result = SSHKeyResult(success=False, generated=generated, error=error_msg)
    else:
        result = _finish_control_plane_key_setup(
            private_key=private_key,
            public_key=public_key,
            keys_dir=keys_dir,
            generated=generated,
        )
    return result


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

    generated, error_msg = _ensure_keypair(
        private_key=private_key,
        comment="aptl-kali-pivot",
        label="ssh-keygen (pivot)",
    )
    if error_msg:
        result = SSHKeyResult(success=False, generated=generated, error=error_msg)
    else:
        result = _finish_pivot_key_setup(
            private_key=private_key,
            public_key=public_key,
            generated=generated,
        )
    return result


def ensure_workstation_pivot_key(pivot_dir: Path) -> SSHKeyResult:
    """Ensure the workstation-to-victim pivot keypair exists.

    Scenario content mirroring the kali pivot key above: workstation SSHes
    into victim as part of the Prime scenario's lateral-movement path. The
    legacy hand-authored workstation entrypoint generated this keypair itself
    at container start (a throwaway ``dev-user`` identity); the SDL-declared
    node has no entrypoint to do that, so it is generated here instead and
    placed the same way (private half on workstation, public half authorized
    on victim only) — issue #581.

    Both halves live in ``pivot_dir`` alongside the kali pivot keypair.
    """
    pivot_dir.mkdir(parents=True, exist_ok=True)

    private_key = pivot_dir / _WORKSTATION_PIVOT_KEY_NAME
    public_key = pivot_dir / f"{_WORKSTATION_PIVOT_KEY_NAME}.pub"

    generated, error_msg = _ensure_keypair(
        private_key=private_key,
        comment="aptl-workstation-pivot",
        label="ssh-keygen (workstation pivot)",
    )
    if error_msg:
        return SSHKeyResult(success=False, generated=generated, error=error_msg)
    return _finish_pivot_key_setup(
        private_key=private_key,
        public_key=public_key,
        generated=generated,
    )


def _ensure_keypair(
    private_key: Path,
    comment: str,
    label: str,
) -> tuple[bool, str]:
    """Ensure a keypair exists, returning ``(generated, error)``."""
    if private_key.exists():
        log.debug("SSH key already exists at %s", private_key)
        return False, ""

    log.info("Generating SSH key pair at %s", private_key)
    error_msg = _run_ssh_keygen(private_key, comment, label)
    if error_msg:
        return False, error_msg

    log.info("SSH key pair generated successfully")
    return True, ""


def ensure_target_authorized_keys(keys_dir: Path, pivot_dir: Path) -> SSHKeyResult:
    """Write the combined authorized_keys file SSH-reachable targets receive.

    SEC #417: a target (victim, workstation, ...) authorizes both the
    operator/MCP control-plane public key and the kali pivot public key — the
    pivot key is what makes kali's in-scenario SSH into the target work. kali
    itself is authorized separately with only the control-plane key (it is
    the pivot key's *private* half that lives on kali, never its own
    authorized_keys). Requires both keypairs to already exist (from
    ``ensure_ssh_keys`` / ``ensure_pivot_key``, always called first).
    """
    control_plane_pub = keys_dir / f"{_KEY_NAME}.pub"
    pivot_pub = pivot_dir / f"{_PIVOT_KEY_NAME}.pub"
    for path in (control_plane_pub, pivot_pub):
        if not path.exists():
            return SSHKeyResult(
                success=False, generated=False, error=f"Public key not found at {path}"
            )
    combined = _with_trailing_newline(control_plane_pub.read_text()) + _with_trailing_newline(
        pivot_pub.read_text()
    )
    target_file = keys_dir / "target_authorized_keys"
    target_file.write_text(combined)
    permission_error = _set_public_key_mode(target_file)
    if permission_error:
        return SSHKeyResult(success=False, generated=False, error=permission_error)
    return SSHKeyResult(success=True, generated=False, key_path=target_file)


def ensure_victim_authorized_keys(keys_dir: Path, pivot_dir: Path) -> SSHKeyResult:
    """Write victim's authorized_keys: control-plane + kali pivot + workstation pivot.

    Victim additionally trusts the workstation pivot key so the Prime
    scenario's workstation -> victim lateral-movement path is already wired
    up by the time materialization completes. Workstation itself does not
    receive this key back (it is the one holding the private half, not
    authorizing it), which is why victim needs a distinct authorized_keys
    file rather than sharing ``target_authorized_keys`` (issue #581 — this
    replaces a runtime "plant the key" step scripts/seed-prime.sh used to
    perform against the legacy workstation entrypoint's throwaway keypair).
    Requires all three keypairs to already exist.
    """
    control_plane_pub = keys_dir / f"{_KEY_NAME}.pub"
    kali_pivot_pub = pivot_dir / f"{_PIVOT_KEY_NAME}.pub"
    workstation_pivot_pub = pivot_dir / f"{_WORKSTATION_PIVOT_KEY_NAME}.pub"
    for path in (control_plane_pub, kali_pivot_pub, workstation_pivot_pub):
        if not path.exists():
            return SSHKeyResult(
                success=False, generated=False, error=f"Public key not found at {path}"
            )
    combined = "".join(
        _with_trailing_newline(path.read_text())
        for path in (control_plane_pub, kali_pivot_pub, workstation_pivot_pub)
    )
    target_file = keys_dir / "victim_authorized_keys"
    target_file.write_text(combined)
    permission_error = _set_public_key_mode(target_file)
    if permission_error:
        return SSHKeyResult(success=False, generated=False, error=permission_error)
    return SSHKeyResult(success=True, generated=False, key_path=target_file)


def _with_trailing_newline(text: str) -> str:
    """Return ``text`` guaranteed to end with a single newline."""
    return text if text.endswith("\n") else text + "\n"


def _finish_control_plane_key_setup(
    private_key: Path,
    public_key: Path,
    keys_dir: Path,
    generated: bool,
) -> SSHKeyResult:
    """Harden and distribute the operator control-plane public key."""
    if not public_key.exists():
        return SSHKeyResult(
            success=False,
            generated=generated,
            error=f"Public key not found at {public_key}",
        )

    permission_error = _harden_key_files(private_key, public_key)
    if permission_error:
        return SSHKeyResult(success=False, generated=generated, error=permission_error)

    pub_content = public_key.read_text()
    (keys_dir / f"{_KEY_NAME}.pub").write_text(pub_content)
    (keys_dir / "authorized_keys").write_text(pub_content)
    log.debug("Public key distributed to %s", keys_dir)
    return SSHKeyResult(success=True, generated=generated, key_path=private_key)


def _finish_pivot_key_setup(
    private_key: Path,
    public_key: Path,
    generated: bool,
) -> SSHKeyResult:
    """Harden the kali pivot private key."""
    if not public_key.exists():
        return SSHKeyResult(
            success=False,
            generated=generated,
            error=f"Pivot public key not found at {public_key}",
        )

    permission_error = _harden_private_key(private_key)
    if permission_error:
        return SSHKeyResult(success=False, generated=generated, error=permission_error)

    return SSHKeyResult(success=True, generated=generated, key_path=private_key)


def _harden_key_files(private_key: Path, public_key: Path) -> str:
    """Apply host-appropriate key permissions and return an error string."""
    permission_error = _harden_private_key(private_key)
    if permission_error:
        return permission_error
    return _set_public_key_mode(public_key)


def _run_ssh_keygen(private_key: Path, comment: str, label: str) -> str:
    """Generate an ed25519 key pair and return an error string on failure."""
    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(private_key),
                "-N",
                "",
                "-C",
                comment,
            ],
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        error_msg = f"{label} failed: {exc}"
        log.error(error_msg)
        return error_msg

    if result.returncode == 0:
        return ""
    error_msg = result.stderr.strip() or result.stdout.strip() or f"{label} failed"
    log.error("%s failed: %s", label, error_msg)
    return error_msg


def _harden_private_key(path: Path) -> str:
    """Restrict a private key to the current host user."""
    if hostenv.is_windows():
        return _harden_private_key_windows(path)
    return _chmod_key(path, 0o600, "private key")


def _set_public_key_mode(path: Path) -> str:
    """Set a public-key mode where POSIX modes apply."""
    if hostenv.is_windows():
        return ""
    return _chmod_key(path, 0o644, "public key")


def _chmod_key(path: Path, mode: int, label: str) -> str:
    """Apply a POSIX mode to a key file and return an error string on failure."""
    try:
        os.chmod(path, mode)
    except (OSError, NotImplementedError) as exc:
        return f"Could not set {label} permissions on {path}: {exc}"
    return ""


def _harden_private_key_windows(path: Path) -> str:
    """Restrict a Windows private key with NTFS ACLs for OpenSSH."""
    account = getpass.getuser()
    try:
        result = subprocess.run(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"{account}:R",
            ],
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return f"icacls failed for {path}: {exc}"
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "unknown error"
        return f"icacls failed for {path}: {details}"
    return ""
