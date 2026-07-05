"""Host- and container-level docker query/inspect operations.

Split out of ``docker_compose.py`` (module-length budget) as a mixin so the
deployment backend stays under the size limit. ``ComposeQueryMixin`` is mixed
into ``DockerComposeBackend``, which supplies ``_run``, ``_run_streaming``, and
``_project_name``.
"""

import subprocess
import json
from typing import Any

from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")

# Bound for snapshot / host-inventory probes. A stalled docker daemon
# (especially the SSH transport) must not hang `aptl lab status --json`
# or the lab-start snapshot step indefinitely.
_HOST_INVENTORY_TIMEOUT = 15


def _parse_labels(labels_str: str) -> dict[str, str]:
    """Parse a comma-separated `k=v,k=v` labels string from `docker ps`."""
    if not labels_str:
        return {}
    out: dict[str, str] = {}
    for pair in labels_str.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _parse_ports(ports_str: str) -> list[str]:
    """Parse a comma-separated ports string from `docker ps`."""
    if not ports_str:
        return []
    return [p.strip() for p in ports_str.split(",") if p.strip()]


def _parse_lab_row(line: str) -> dict[str, Any] | None:
    """Parse a single TSV row from `docker ps --format ...` into a dict.

    Returns ``None`` for short / malformed lines so callers can filter
    them out cleanly.
    """
    parts = line.split("\t", 5)
    if len(parts) < 5:
        return None
    return {
        "name": parts[0],
        "image": parts[1],
        "id": parts[2],
        "status": parts[3],
        "labels": _parse_labels(parts[4]),
        "ports": _parse_ports(parts[5] if len(parts) > 5 else ""),
    }


def _select_shell(probe_returncode: int) -> tuple[str, bool]:
    """Decide which shell ``container_shell`` should launch.

    Pure logic so the decision table is unit-testable without mocking
    subprocess. Returns ``(shell_path, should_run)``: when ``should_run``
    is False, the caller should surface the probe error instead.
    """
    if probe_returncode == 0:
        return "/bin/bash", True
    if probe_returncode in (126, 127):
        return "/bin/sh", True
    return "", False


def _decode_first_object(stdout: str) -> dict[str, Any]:
    """Return the first object of a docker ``inspect`` JSON array, or ``{}``."""
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else {}
    return parsed if isinstance(parsed, dict) else {}


def _decode_compose_ps(stdout: str) -> list[dict[str, Any]]:
    """Parse ``docker compose ps --format json`` output (NDJSON or array)."""
    stripped = stdout.strip()
    if not stripped:
        return []
    try:
        if stripped.startswith("["):
            parsed = json.loads(stripped)
        else:
            parsed = [
                json.loads(line) for line in stripped.splitlines() if line.strip()
            ]
    except json.JSONDecodeError:
        log.warning("could not parse compose ps output")
        return []
    return parsed


class ComposeQueryMixin(object):
    """Docker host/container query + inspect operations for the backend.

    Mixed into ``DockerComposeBackend``, which supplies the ``_run`` and
    ``_run_streaming`` subprocess runners and the ``_project_name``
    attribute that the methods below depend on.
    """

    # Host inventory (CLI-004 / ADR-023) ----------------------------------

    def host_versions(self) -> dict[str, str]:
        result = {"docker": "", "compose": ""}
        docker_out = self._run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if docker_out.returncode == 0:
            result["docker"] = docker_out.stdout.strip()
        compose_out = self._run(
            ["docker", "compose", "version", "--short"],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if compose_out.returncode == 0:
            result["compose"] = compose_out.stdout.strip()
        return result

    def host_list_lab_containers(self) -> list[dict[str, Any]]:
        # Scope to the configured compose project via the standard
        # com.docker.compose.project label rather than just the
        # ``aptl-`` name prefix, so a snapshot taken against a shared
        # SSH daemon doesn't expose other tenants' containers that
        # happen to use the same naming convention.
        fmt = "{{.Names}}\t{{.Image}}\t{{.ID}}\t{{.Status}}\t{{.Labels}}\t{{.Ports}}"
        result = self._run(
            [
                "docker", "ps", "-a",
                "--filter", f"label=com.docker.compose.project={self._project_name}",
                "--filter", "name=aptl-",
                "--format", fmt,
            ],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        return [
            row
            for row in (_parse_lab_row(line) for line in result.stdout.splitlines())
            if row is not None
        ]

    def host_list_lab_networks(self, name_prefix: str) -> list[str]:
        # Scope to the current compose project's networks. Combined with
        # the user-supplied name prefix, this prevents leaking other
        # tenants' aptl-* networks on a shared SSH daemon.
        result = self._run(
            [
                "docker", "network", "ls",
                "--filter", f"label=com.docker.compose.project={self._project_name}",
                "--filter", f"name={name_prefix}",
                "--format", "{{.Name}}",
            ],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if result.returncode != 0:
            return []
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

    def host_list_networks(self) -> list[str]:
        """List every Docker network visible to the backend daemon."""

        result = self._run(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if result.returncode != 0:
            return []
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

    def host_inspect_network(self, name: str) -> dict[str, Any]:
        result = self._run(
            ["docker", "network", "inspect", name],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        payload = (
            _decode_first_object(result.stdout)
            if result.returncode == 0 and result.stdout.strip()
            else {}
        )
        if not payload:
            return {}
        ipam = (payload.get("IPAM", {}).get("Config") or [{}])[0]
        containers_map = payload.get("Containers", {})
        labels = payload.get("Labels")
        if not isinstance(labels, dict):
            labels = {}
        return {
            "name": name,
            "internal": bool(payload.get("Internal", False)),
            "subnet": ipam.get("Subnet", ""),
            "gateway": ipam.get("Gateway", ""),
            "labels": {str(key): str(value) for key, value in labels.items()},
            "containers": sorted(c.get("Name", "") for c in containers_map.values()),
        }

    # Container interaction (CLI-004, ADR-023) ----------------------------

    def container_list(
        self, *, all_containers: bool = True
    ) -> list[dict[str, Any]]:
        cmd = ["docker", "compose", "-p", self._project_name, "ps"]
        if all_containers:
            cmd.append("-a")
        cmd.extend(["--format", "json"])
        result = self._run(cmd)
        if result.returncode != 0:
            log.warning("container_list failed: %s", result.stderr.strip())
            return []
        return _decode_compose_ps(result.stdout)

    def container_logs(
        self,
        name: str,
        *,
        follow: bool = False,
        tail: int | None = None,
    ) -> int:
        cmd = ["docker", "logs"]
        if follow:
            cmd.append("-f")
        if tail is not None:
            cmd.extend(["--tail", str(tail)])
        cmd.append(name)
        return self._run_streaming(cmd)

    def container_logs_capture(
        self,
        name: str,
        *,
        since: str | None = None,
        until: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        cmd = ["docker", "logs"]
        if since is not None:
            cmd.extend(["--since", since])
        if until is not None:
            cmd.extend(["--until", until])
        cmd.append(name)
        return self._run(cmd, timeout=timeout)

    def container_shell(
        self, name: str, *, shell: str | None = None
    ) -> int:
        if shell is not None:
            return self._run_streaming(["docker", "exec", "-it", name, shell])
        # Probe non-interactively for bash before launching the TTY,
        # then run exactly one interactive shell. See ADR-023.
        probe = self._run(["docker", "exec", name, "/bin/bash", "-c", "true"])
        chosen, should_run = _select_shell(probe.returncode)
        if not should_run:
            log.warning(
                "container_shell probe of %s failed (exit %d): %s",
                name, probe.returncode, probe.stderr.strip(),
            )
            return probe.returncode
        if chosen == "/bin/sh":
            log.info("bash unavailable in %s; using /bin/sh", name)
        return self._run_streaming(["docker", "exec", "-it", name, chosen])

    def container_exec(
        self,
        name: str,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        argv = ["docker", "exec", name, *cmd]
        return self._run(argv, timeout=timeout)

    def container_exists(self, name: str) -> bool:
        info = self.container_inspect(name)
        if not info:
            return False
        labels = info.get("Config", {}).get("Labels") or {}
        if not isinstance(labels, dict):
            return False
        # Containers managed by this compose project carry the standard
        # com.docker.compose.project label. On a shared daemon this
        # rejects names that exist but belong to a different project.
        return labels.get("com.docker.compose.project") == self._project_name

    def container_inspect(self, name: str) -> dict[str, Any]:
        result = self._run(
            ["docker", "inspect", name],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if result.returncode != 0:
            log.debug("container_inspect failed for %s: %s", name, result.stderr.strip())
            return {}
        return _decode_first_object(result.stdout)
