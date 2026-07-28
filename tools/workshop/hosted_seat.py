#!/usr/bin/env python3
"""Prepare create-once local state for the issue #825 hosted-seat runbook."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NamedTuple

from aptl.utils.pathsafe import create_exclusive_nofollow


_SEAT_ID = re.compile(r"^seat(?:0[1-9]|1[0-2])$")
_TRIAL_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_AWS_PROFILE = "catalyst-dev"
_AWS_REGION = "us-east-2"


class PreparedSeat(NamedTuple):
    """Paths written for one admitted seat without its secret value."""

    state_dir: Path
    seat_id: str
    hostname: str
    credential_file: Path
    ledger_file: Path
    dcv_config_file: Path
    dcv_permissions_file: Path
    caddyfile: Path
    host_ports_file: Path

    def public_summary(self) -> str:
        """Return a deterministic machine summary that contains no passphrase."""

        return json.dumps(
            {
                "seat_id": self.seat_id,
                "hostname": self.hostname,
                "state_dir": str(self.state_dir),
                "credential_file": str(self.credential_file),
                "ledger_file": str(self.ledger_file),
                "dcv_config_file": str(self.dcv_config_file),
                "dcv_permissions_file": str(self.dcv_permissions_file),
                "caddyfile": str(self.caddyfile),
                "host_ports_file": str(self.host_ports_file),
            },
            sort_keys=True,
        )


class McpRegistrationSpec(NamedTuple):
    """One validated process registration read from operator-owned lab state."""

    argv: tuple[str, ...]
    env: dict[str, str]


def validate_seat_id(seat_id: str) -> str:
    """Require one of the twelve issue-authorized seat identifiers."""

    if not _SEAT_ID.fullmatch(seat_id):
        raise ValueError("seat id must be seat01 through seat12")
    return seat_id


def validate_hostname(hostname: str) -> str:
    """Require a canonical lowercase DNS hostname rather than a URL or wildcard."""

    labels = hostname.split(".")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_ip = False
    else:
        is_ip = True
    if (
        hostname != hostname.lower()
        or len(hostname) > 253
        or len(labels) < 3
        or is_ip
        or any(not _DNS_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("hostname must be a canonical lowercase DNS hostname")
    return hostname


def validate_seat_hostname(seat_id: str, hostname: str) -> tuple[str, str]:
    """Bind a canonical seat identifier to its one exact hostname."""

    seat = validate_seat_id(seat_id)
    host = validate_hostname(hostname)
    if not host.startswith(f"{seat}."):
        raise ValueError(f"hostname must start with {seat}.")
    return seat, host


def render_dcv_config(hostname: str) -> str:
    """Render the security-sensitive DCV server projection."""

    host = validate_hostname(hostname)
    exact_host = re.escape(host)
    return (
        "[connectivity]\n"
        "web-port=8443\n"
        "web-listen-endpoints=['127.0.0.1:8443', '[::1]:8443']\n"
        "enable-quic-frontend=false\n"
        "idle-timeout=120\n"
        "\n"
        "[security]\n"
        'authentication="system"\n'
        'pam-service-name="dcv"\n'
        "authentication-threshold=3\n"
        "max-connections-per-user=1\n"
        f'allowed-http-host-regex="^{exact_host}(:443)?$"\n'
        f'allowed-ws-origin-regex="^https://{exact_host}(:443)?$"\n'
        f'server-fqdn="{host}"\n'
        "\n"
        "[session-management]\n"
        "max-concurrent-sessions=1\n"
        "max-sessions-per-user=1\n"
        "max-concurrent-clients=1\n"
    )


def render_caddyfile(hostname: str) -> str:
    """Render one exact-host Caddy proxy with verified loopback TLS."""

    host = validate_hostname(hostname)
    return (
        "{\n"
        "\tadmin 127.0.0.1:2019\n"
        "\tservers {\n"
        "\t\tprotocols h1 h2\n"
        "\t}\n"
        "}\n"
        "\n"
        f"{host} {{\n"
        "\treverse_proxy https://127.0.0.1:8443 {\n"
        f"\t\theader_up Host {host}\n"
        "\t\ttransport http {\n"
        "\t\t\ttls_trust_pool file /etc/dcv/dcv-upstream-ca.pem\n"
        f"\t\t\ttls_server_name {host}\n"
        "\t\t\tdial_timeout 5s\n"
        "\t\t\tresponse_header_timeout 30s\n"
        "\t\t}\n"
        "\t}\n"
        "}\n"
    )


def render_dcv_permissions() -> str:
    """Grant the seat owner only the features required for the workshop."""

    return "[permissions]\n%owner% allow display keyboard mouse pointer audio-out\n"


def host_port_overrides() -> dict[str, str]:
    """Return the common APTL overrides that reserve 443 and 8443."""

    return {
        "APTL_HP_WAZUH_DASHBOARD_5601": "9443",
        "APTL_HP_MISP_443": "9444",
    }


def load_mcp_registration_specs(
    project_dir: Path, server_ids: Sequence[str]
) -> dict[str, McpRegistrationSpec]:
    """Select the exact admitted MCP processes without loading extra secrets."""

    project = project_dir.resolve()
    document = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
    servers = document.get("mcpServers") if isinstance(document, dict) else None
    if not isinstance(servers, dict):
        raise ValueError("invalid MCP registration document")
    selected: dict[str, McpRegistrationSpec] = {}
    for server_id in server_ids:
        raw = servers.get(server_id)
        if raw is None:
            raise ValueError(f"missing MCP registration: {server_id}")
        if not isinstance(raw, dict):
            raise ValueError(f"invalid MCP registration: {server_id}")
        command = raw.get("command")
        args = raw.get("args", [])
        environment = raw.get("env", {})
        if (
            not isinstance(command, str)
            or not command
            or not isinstance(args, list)
            or any(not isinstance(item, str) for item in args)
            or not isinstance(environment, dict)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in environment.items()
            )
        ):
            raise ValueError(f"invalid MCP registration: {server_id}")
        selected[server_id] = McpRegistrationSpec(
            argv=(command, *args),
            env=dict(environment),
        )
    return selected


def run_semantic_mcp_smoke(
    project_dir: Path,
    profile_path: Path | None = None,
    profile_root: Path | None = None,
) -> tuple[dict[str, str], ...]:
    """Run the profile's real red-to-blue MCP operations and redact responses."""

    from aptl.validation.participant_mcp_smoke import (
        McpRegistration,
        run_participant_mcp_smoke,
    )
    from aptl.validation.participant_profile import load_participant_profile

    project = project_dir.resolve()
    binding_root = (profile_root or project).resolve()
    selected_profile = profile_path or (
        binding_root / "participant-profiles" / "guided-purple-v1" / "profile.json"
    )
    profile = load_participant_profile(binding_root, selected_profile)
    specs = load_mcp_registration_specs(project, profile.mcp_server_ids)
    safe_environment = {
        key: value
        for key in ("HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "USER")
        if (value := os.environ.get(key)) is not None
    }
    registrations = {
        server_id: McpRegistration(
            argv=spec.argv,
            cwd=project,
            env={**safe_environment, **spec.env},
        )
        for server_id, spec in specs.items()
    }
    evidence = run_participant_mcp_smoke(profile, registrations)
    return tuple(
        {
            "check_id": item.check_id,
            "status": item.status,
            "summary": item.summary,
        }
        for item in evidence
    )


def _ensure_private_directory(path: Path) -> None:
    """Create or admit one owner-only directory without following a symlink."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"state directory must not be a symlink: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"state path must be a directory: {path}")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError(f"state directory must be owner-only (0700): {path}")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _create_private_file(base_dir: Path, relative: Path, content: bytes) -> Path:
    create_exclusive_nofollow(base_dir, relative, content)
    path = base_dir / relative
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError(f"created file is not owner-only: {relative}")
    return path


def _passphrase(token_bytes: Callable[[int], bytes]) -> str:
    return base64.urlsafe_b64encode(token_bytes(32)).rstrip(b"=").decode("ascii")


def prepare_seat(
    *,
    state_dir: Path,
    trial_id: str,
    seat_id: str,
    hostname: str,
    token_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> PreparedSeat:
    """Create the secret and deterministic configuration for one seat exactly once."""

    seat, host = validate_seat_hostname(seat_id, hostname)
    if not _TRIAL_ID.fullmatch(trial_id):
        raise ValueError("trial id must be a bounded lowercase identifier")
    state = state_dir.absolute()
    _ensure_private_directory(state)
    for relative in (
        Path("credentials"),
        Path("ledgers"),
        Path("generated"),
        Path("generated") / seat,
    ):
        _ensure_private_directory(state / relative)

    passphrase = _passphrase(token_bytes)
    credential_file = _create_private_file(
        state,
        Path("credentials") / f"{seat}.json",
        _json_bytes({"username": seat, "passphrase": passphrase}),
    )
    ledger = {
        "schema": "aptl.hosted-seat-input/v1",
        "trial_id": trial_id,
        "seat_id": seat,
        "username": seat,
        "hostname": host,
        "dcv_upstream": "https://127.0.0.1:8443",
        "aws_profile": _AWS_PROFILE,
        "aws_region": _AWS_REGION,
    }
    ledger_file = _create_private_file(
        state, Path("ledgers") / f"{seat}.json", _json_bytes(ledger)
    )
    generated = Path("generated") / seat
    dcv_config_file = _create_private_file(
        state, generated / "dcv.conf", render_dcv_config(host).encode()
    )
    dcv_permissions_file = _create_private_file(
        state, generated / f"{seat}.perm", render_dcv_permissions().encode()
    )
    caddyfile = _create_private_file(
        state, generated / "Caddyfile", render_caddyfile(host).encode()
    )
    host_ports_file = _create_private_file(
        state,
        generated / "aptl-host-ports.env",
        "".join(
            f"{key}={value}\n" for key, value in host_port_overrides().items()
        ).encode(),
    )
    return PreparedSeat(
        state_dir=state,
        seat_id=seat,
        hostname=host,
        credential_file=credential_file,
        ledger_file=ledger_file,
        dcv_config_file=dcv_config_file,
        dcv_permissions_file=dcv_permissions_file,
        caddyfile=caddyfile,
        host_ports_file=host_ports_file,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare create-once local state for one hosted APTL seat."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--state-dir", type=Path, required=True)
    prepare.add_argument("--trial-id", required=True)
    prepare.add_argument("--seat-id", required=True)
    prepare.add_argument("--hostname", required=True)
    smoke = subparsers.add_parser("smoke")
    smoke.add_argument("--project-dir", type=Path, required=True)
    smoke.add_argument("--profile-path", type=Path)
    smoke.add_argument("--profile-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the helper and print only the non-secret result."""

    arguments = _parser().parse_args(argv)
    if arguments.command == "prepare":
        result = prepare_seat(
            state_dir=arguments.state_dir,
            trial_id=arguments.trial_id,
            seat_id=arguments.seat_id,
            hostname=arguments.hostname,
        )
        print(result.public_summary())
        return 0
    evidence = run_semantic_mcp_smoke(
        arguments.project_dir, arguments.profile_path, arguments.profile_root
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0 if all(item["status"] == "passed" for item in evidence) else 1


if __name__ == "__main__":
    sys.exit(main())
