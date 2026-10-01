#!/usr/bin/python3
"""Give the disposable desktop account its live, guest-local MCP inputs."""

from __future__ import annotations

import json
import os
import pwd
import re
import ipaddress
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROLES = {
    "red": ("aptl-red",),
    "blue": (
        "aptl-wazuh",
        "aptl-indexer",
        "aptl-network",
        "aptl-threatintel",
        "aptl-casemgmt",
        "aptl-soar",
    ),
}

_SECURITY_NETWORK = ipaddress.ip_network("172.20.0.0/24")
_HOSTS_MARKER = "# aptl-seat-browser"


def _regular(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError("seat desktop input is missing or unsafe")
    return path


def _private_file(path: Path, payload: bytes, uid: int, gid: int) -> None:
    if path.is_symlink():
        raise ValueError("seat desktop destination is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".seat-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
        os.chown(temporary, uid, gid)
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _desktop_config(
    source: dict,
    project: Path,
    names: tuple[str, ...],
    run_id: str,
    run_store: Path,
) -> bytes:
    servers = source.get("mcpServers")
    if not isinstance(servers, dict):
        raise ValueError("seat desktop MCP source is invalid")
    selected = {}
    for name in names:
        item = servers.get(name)
        if not isinstance(item, dict) or not isinstance(item.get("env"), dict):
            raise ValueError("seat desktop MCP registration is incomplete")
        args = item.get("args")
        if not isinstance(args, list) or len(args) != 1 or not isinstance(args[0], str):
            raise ValueError("seat desktop MCP artifact is invalid")
        artifact = (project / args[0]).resolve()
        if (
            not artifact.is_relative_to((project / "mcp").resolve())
            or not artifact.is_file()
        ):
            raise ValueError("seat desktop MCP artifact is missing")
        if not all(
            isinstance(k, str) and isinstance(v, str) for k, v in item["env"].items()
        ):
            raise ValueError("seat desktop MCP environment is invalid")
        environment = dict(item["env"])
        environment.update(
            {
                "APTL_MCP_ADMITTED_RUN_ID": run_id,
                "APTL_MCP_RUN_STORE_BASE": str(run_store),
                "APTL_STATE_DIR": str(project / ".aptl"),
            }
        )
        selected[name] = {
            "command": "/usr/bin/node",
            "args": [str(artifact)],
            "env": environment,
        }
    return (json.dumps({"mcpServers": selected}, separators=(",", ":")) + "\n").encode()


def _run_store(project: Path) -> Path:
    config = json.loads(_regular(project / "aptl.json").read_text())
    try:
        name = config["run_storage"]["local_path"]
    except (KeyError, TypeError):
        name = "./runs"
    if not isinstance(name, str) or not name:
        raise ValueError("seat desktop run store is unavailable")
    run_store = Path(name)
    if not run_store.is_absolute():
        run_store = project / run_store
    if not run_store.is_absolute() or not run_store.resolve().is_relative_to(
        project.resolve()
    ):
        raise ValueError("seat desktop run store escapes the guest project")
    if not run_store.is_dir() or run_store.is_symlink():
        raise ValueError("seat desktop run store is unsafe")
    return run_store.resolve()


def _assign_run_store(run_store: Path, uid: int, gid: int) -> None:
    for root, directories, files in os.walk(run_store, followlinks=False):
        directory = Path(root)
        if directory.is_symlink() or any(
            (directory / name).is_symlink() for name in (*directories, *files)
        ):
            raise ValueError("seat desktop run store contains a link")
        os.chown(directory, uid, gid)
        for name in files:
            os.chown(directory / name, uid, gid)


def _grant_lifecycle_read(project: Path, gid: int) -> None:
    """Let the desktop inspect this guest's lab without editing root receipts."""

    root = project / ".aptl"
    lifecycle = root / "lifecycle"
    if not lifecycle.is_dir() or root.is_symlink() or lifecycle.is_symlink():
        raise ValueError("seat lab ownership state is unavailable")
    for base, directories, files in os.walk(lifecycle, followlinks=False):
        parent = Path(base)
        if parent.is_symlink() or any(
            (parent / name).is_symlink() for name in (*directories, *files)
        ):
            raise ValueError("seat lab ownership state contains a link")
        for path in (parent, *(parent / name for name in directories)):
            os.chown(path, -1, gid)
            path.chmod(stat.S_IMODE(path.stat().st_mode) | 0o050)
        for name in files:
            path = parent / name
            if not path.is_file():
                raise ValueError("seat lab ownership state contains a non-file")
            os.chown(path, -1, gid)
            path.chmod(stat.S_IMODE(path.stat().st_mode) | 0o040)
    os.chown(root, -1, gid)
    root.chmod(stat.S_IMODE(root.stat().st_mode) | 0o050)


def _misp_security_ip() -> str:
    """Read the live scenario address, not a guessed Compose allocation."""

    names = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.splitlines()
    misp = [name for name in names if name.endswith("-misp")]
    if len(misp) != 1:
        raise ValueError("seat MISP browser target is unavailable")
    networks = json.loads(
        subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                misp[0],
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
    )
    addresses = [
        value.get("IPAddress")
        for name, value in networks.items()
        if name.endswith("_aptl-security") and isinstance(value, dict)
    ]
    if len(addresses) != 1:
        raise ValueError("seat MISP security address is unavailable")
    try:
        address = ipaddress.ip_address(addresses[0])
    except ValueError as exc:
        raise ValueError("seat MISP security address is invalid") from exc
    if address not in _SECURITY_NETWORK:
        raise ValueError("seat MISP security address is out of range")
    return str(address)


def _browser_hosts(path: Path, misp_ip: str) -> None:
    """Publish only the two browser names whose certificates require them."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("seat browser hosts file is unsafe")
    existing = [
        line for line in path.read_text().splitlines() if _HOSTS_MARKER not in line
    ]
    payload = (
        "\n".join(
            (
                *existing,
                f"127.0.0.1 wazuh.dashboard {_HOSTS_MARKER}",
                f"{misp_ip} misp.techvault.local {_HOSTS_MARKER}",
            )
        )
        + "\n"
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=".hosts-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(payload)
        temporary.chmod(stat.S_IMODE(path.stat().st_mode))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _configure_browser_access(project: Path) -> None:
    """Trust public scenario CAs and resolve the authored browser origins."""

    trust = Path("/usr/local/share/ca-certificates")
    for source, name in (
        (project / "config/wazuh_indexer_ssl_certs/root-ca.pem", "aptl-wazuh.crt"),
        (project / "config/soc_certs/lab-ca.pem", "aptl-soc.crt"),
    ):
        _regular(source)
        destination = trust / name
        if destination.is_symlink():
            raise ValueError("seat browser trust destination is unsafe")
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
    subprocess.run(
        ["update-ca-certificates"],
        check=True,
        capture_output=True,
        timeout=30,
    )
    _browser_hosts(Path("/etc/hosts"), _misp_security_ip())


def handoff(
    project: Path,
    home: Path,
    supervisor_home: Path,
    uid: int,
    gid: int,
    run_id: str,
) -> None:
    """Publish live role configs, lab SSH key, and only the needed guest state."""

    source = json.loads(_regular(project / ".mcp.json").read_text())
    if not isinstance(source, dict):
        raise ValueError("seat desktop MCP source is invalid")
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id) is None
        or ".." in run_id
    ):
        raise ValueError("seat desktop run identity is invalid")
    run_store = _run_store(project)
    configs = {
        role: _desktop_config(source, project, names, run_id, run_store)
        for role, names in ROLES.items()
    }
    env_path = _regular(project / ".env")
    key = _regular(supervisor_home / ".ssh" / "aptl_lab_key").read_bytes()
    if not key:
        raise ValueError("seat desktop SSH identity is empty")
    if home.is_symlink() or not home.is_dir():
        raise ValueError("seat desktop home is unsafe")
    ssh_dir = home / ".ssh"
    state_dir = home / ".config" / "aptl"
    for directory in (ssh_dir, state_dir):
        if directory.is_symlink():
            raise ValueError("seat desktop private directory is unsafe")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        os.chown(directory, uid, gid)
    # MCP loaders resolve their own docker-lab-config.json beneath the project,
    # then search ancestor directories for .env. Give this guest account read
    # access only after the live lab has generated those values.
    os.chown(env_path, -1, gid)
    env_path.chmod(0o640)
    _assign_run_store(run_store, uid, gid)
    _grant_lifecycle_read(project, gid)
    _configure_browser_access(project)
    ca_dir = project / "config" / "soc_certs"
    ca = ca_dir / "lab-ca.pem"
    if ca.is_file() and not ca.is_symlink() and not ca_dir.is_symlink():
        os.chown(ca_dir, -1, gid)
        ca_dir.chmod(0o710)
        os.chown(ca, -1, gid)
        ca.chmod(0o640)
    _private_file(ssh_dir / "aptl_lab_key", key, uid, gid)
    for role, payload in configs.items():
        _private_file(home / f"{role}.mcp.json", payload, uid, gid)
    if os.environ.get("APTL_SEAT_DESKTOP_MCP_SMOKE") == "1":
        subprocess.run(
            ["/usr/bin/python3", "/opt/aptl/desktop/desktop-mcp-smoke.py"],
            cwd=project,
            env={**os.environ, "HOME": str(home), "USER": "aptl", "LOGNAME": "aptl"},
            user=uid,
            group=gid,
            check=True,
            timeout=210,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    _private_file(state_dir / "run-ready", b"ready\n", uid, gid)


if __name__ == "__main__":
    account = pwd.getpwnam("aptl")
    handoff(
        Path(sys.argv[1]),
        Path(account.pw_dir),
        Path.home(),
        account.pw_uid,
        account.pw_gid,
        sys.argv[2],
    )
