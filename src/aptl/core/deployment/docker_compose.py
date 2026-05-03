"""Docker Compose deployment backend.

Implements the DeploymentBackend protocol using local Docker Compose
subprocess calls. This is the default backend and wraps the logic
previously embedded directly in lab.py and kill.py.
"""

import json
import subprocess
from pathlib import Path

from aptl.core.lab import LabResult, LabStatus
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")

# Timeout for Docker Compose subprocess calls during kill operations.
# Generous enough for a large stack, short enough that a hung daemon
# won't block the kill switch indefinitely.
_DOCKER_TIMEOUT = 30

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


def _parse_lab_row(line: str) -> dict | None:
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


class DockerComposeBackend:
    """Docker Compose deployment backend.

    Manages lab lifecycle via ``docker compose`` subprocess calls.
    All commands run against the docker-compose.yml in project_dir.
    """

    def __init__(
        self,
        project_dir: Path,
        project_name: str = "aptl",
    ) -> None:
        self._project_dir = project_dir
        self._project_name = project_name

    @property
    def project_dir(self) -> Path:
        return self._project_dir

    @property
    def project_name(self) -> str:
        return self._project_name

    def _build_command(
        self,
        action: str,
        profiles: list[str],
    ) -> list[str]:
        """Build a docker compose command with profile flags.

        Does NOT add action-specific flags (--build, -d, -v); callers
        are responsible for appending those after calling this method.

        Args:
            action: The compose action (up, down, ps, kill, etc.).
            profiles: List of docker compose profiles to activate.

        Returns:
            Command as a list of strings suitable for subprocess.run().
        """
        cmd = ["docker", "compose"]

        for profile in profiles:
            cmd.extend(["--profile", profile])

        cmd.append(action)

        return cmd

    def _run(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess command in the project directory.

        Captures stdout/stderr; suitable for commands whose output the
        caller wants to parse or log.

        Args:
            cmd: Command as a list of strings.
            timeout: Optional timeout in seconds.

        Returns:
            CompletedProcess result.
        """
        kwargs: dict = {
            "capture_output": True,
            "text": True,
            "cwd": self._project_dir,
        }
        if timeout is not None:
            kwargs["timeout"] = timeout
        return subprocess.run(cmd, **kwargs)

    def _run_streaming(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> int:
        """Run a subprocess command inheriting parent stdin/stdout/stderr.

        Used for interactive sessions (``container_shell``) and live log
        streams (``container_logs``). The parent terminal is connected
        directly to the child process — no capturing.

        Args:
            cmd: Command as a list of strings.
            timeout: Optional timeout in seconds.

        Returns:
            Exit code of the child process.
        """
        kwargs: dict = {
            "cwd": self._project_dir,
            "check": False,
        }
        if timeout is not None:
            kwargs["timeout"] = timeout
        return subprocess.run(cmd, **kwargs).returncode

    def start(self, profiles: list[str], *, build: bool = True) -> LabResult:
        """Start lab services via docker compose up.

        Args:
            profiles: List of profile names to activate.
            build: If True, rebuild images before starting.

        Returns:
            LabResult indicating success or failure.
        """
        cmd = self._build_command("up", profiles)
        if build:
            cmd.append("--build")
        cmd.append("-d")

        log.info("Starting lab with profiles: %s", profiles)
        log.debug("Command: %s", " ".join(cmd))

        result = self._run(cmd)

        if result.returncode != 0:
            log.error("Lab start failed: %s", result.stderr)
            return LabResult(success=False, error=result.stderr)

        log.info("Lab started successfully")
        return LabResult(success=True, message="Lab started")

    def stop(
        self, profiles: list[str], *, remove_volumes: bool = False
    ) -> LabResult:
        """Stop lab services via docker compose down.

        Args:
            profiles: List of profile names to include in the stop.
            remove_volumes: If True, also remove Docker volumes (-v flag).

        Returns:
            LabResult indicating success or failure.
        """
        cmd = self._build_command("down", profiles=profiles)
        if remove_volumes:
            cmd.append("-v")

        log.info("Stopping lab (remove_volumes=%s)", remove_volumes)

        result = self._run(cmd)

        if result.returncode != 0:
            log.error("Lab stop failed: %s", result.stderr)
            return LabResult(success=False, error=result.stderr)

        log.info("Lab stopped successfully")
        return LabResult(success=True, message="Lab stopped")

    def status(self) -> LabStatus:
        """Query current lab status via docker compose ps.

        Returns:
            LabStatus with container information.
        """
        cmd = ["docker", "compose", "ps", "--format", "json"]

        result = self._run(cmd)

        if result.returncode != 0:
            log.warning("Could not get lab status: %s", result.stderr)
            return LabStatus(running=False, error=result.stderr)

        try:
            # docker compose ps --format json outputs one JSON object per
            # line (NDJSON), not a JSON array.  Try array first, fall back
            # to NDJSON.
            stripped = result.stdout.strip()
            if not stripped:
                containers: list[dict] = []
            elif stripped.startswith("["):
                containers = json.loads(stripped)
            else:
                containers = [
                    json.loads(line)
                    for line in stripped.splitlines()
                    if line.strip()
                ]
        except json.JSONDecodeError:
            log.warning("Could not parse compose ps output")
            return LabStatus(
                running=False, error="Failed to parse container status"
            )

        running = len(containers) > 0
        return LabStatus(running=running, containers=containers)

    def kill(self, profiles: list[str]) -> tuple[bool, str]:
        """Emergency-stop all lab containers.

        Uses ``docker compose kill`` for immediate SIGKILL, followed by
        ``docker compose down`` to clean up stopped containers.

        Args:
            profiles: List of profile names to include.

        Returns:
            Tuple of (success, error_message).
        """
        # Phase 1: docker compose kill (immediate SIGKILL)
        kill_cmd = ["docker", "compose"]
        for profile in profiles:
            kill_cmd.extend(["--profile", profile])
        kill_cmd.append("kill")

        log.info("Running: %s", " ".join(kill_cmd))
        kill_ok = False
        try:
            result = self._run(kill_cmd, timeout=_DOCKER_TIMEOUT)
            kill_ok = result.returncode == 0
            if not kill_ok:
                log.warning(
                    "docker compose kill stderr: %s", result.stderr.strip()
                )
        except subprocess.TimeoutExpired:
            log.warning(
                "docker compose kill timed out after %ds", _DOCKER_TIMEOUT
            )
        except (FileNotFoundError, OSError) as exc:
            msg = f"docker compose kill failed: {exc}"
            log.error(msg)
            return False, msg

        # Phase 2: docker compose down (cleanup).  Treat non-zero exit as
        # a warning -- the important work (SIGKILL) already happened above.
        down_cmd = self._build_command("down", profiles=profiles)
        log.info("Running: %s", " ".join(down_cmd))
        try:
            result = self._run(down_cmd, timeout=_DOCKER_TIMEOUT)
            if result.returncode != 0:
                log.warning(
                    "docker compose down stderr: %s", result.stderr.strip()
                )
        except subprocess.TimeoutExpired:
            log.warning(
                "docker compose down timed out after %ds", _DOCKER_TIMEOUT
            )
        except (FileNotFoundError, OSError) as exc:
            log.warning("docker compose down failed: %s", exc)

        if not kill_ok:
            return False, "docker compose kill returned non-zero"

        log.info("All lab containers stopped")
        return True, ""

    def pull_images(self, images: list[str]) -> list[str]:
        """Pre-pull container images via docker pull.

        Args:
            images: List of image references to pull.

        Returns:
            List of warning messages for images that failed to pull
            (non-fatal).
        """
        warnings: list[str] = []
        for image in images:
            try:
                result = self._run(["docker", "pull", image])
                if result.returncode != 0:
                    msg = f"Failed to pull {image}: {result.stderr.strip()}"
                    log.warning(msg)
                    warnings.append(msg)
                else:
                    log.info("Pulled %s", image)
            except (FileNotFoundError, OSError) as exc:
                msg = f"Failed to pull {image}: {exc}"
                log.warning(msg)
                warnings.append(msg)
        return warnings

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

    def host_list_lab_containers(self) -> list[dict]:
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

    def host_inspect_network(self, name: str) -> dict:
        result = self._run(
            ["docker", "network", "inspect", name],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            log.debug("host_inspect_network: bad JSON for %s", name)
            return {}
        if isinstance(payload, list):
            payload = payload[0] if payload else {}
        if not isinstance(payload, dict):
            return {}
        subnet = ""
        gateway = ""
        ipam_configs = payload.get("IPAM", {}).get("Config", [])
        if ipam_configs:
            subnet = ipam_configs[0].get("Subnet", "")
            gateway = ipam_configs[0].get("Gateway", "")
        containers_map = payload.get("Containers", {})
        names = sorted(c.get("Name", "") for c in containers_map.values())
        return {
            "name": name,
            "subnet": subnet,
            "gateway": gateway,
            "containers": names,
        }

    # Container interaction (CLI-004, ADR-023) ----------------------------

    def container_list(
        self, *, all_containers: bool = True
    ) -> list[dict]:
        cmd = ["docker", "compose", "-p", self._project_name, "ps"]
        if all_containers:
            cmd.append("-a")
        cmd.extend(["--format", "json"])
        result = self._run(cmd)
        if result.returncode != 0:
            log.warning("container_list failed: %s", result.stderr.strip())
            return []
        stripped = result.stdout.strip()
        if not stripped:
            return []
        try:
            if stripped.startswith("["):
                parsed = json.loads(stripped)
            else:
                parsed = [
                    json.loads(line)
                    for line in stripped.splitlines()
                    if line.strip()
                ]
        except json.JSONDecodeError:
            log.warning("container_list could not parse compose ps output")
            return []
        return parsed

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
        # Probe non-interactively for bash before launching the TTY.
        # Doing the fallback after the interactive shell exits would
        # misinterpret the user's own 126/127 exit codes (e.g. running a
        # non-existent command then `exit`) as "bash missing" and open
        # an unwanted second shell.
        probe = self._run(["docker", "exec", name, "/bin/bash", "-c", "true"])
        if probe.returncode == 0:
            return self._run_streaming(["docker", "exec", "-it", name, "/bin/bash"])
        if probe.returncode in (126, 127):
            log.info("bash unavailable in %s; using /bin/sh", name)
            return self._run_streaming(["docker", "exec", "-it", name, "/bin/sh"])
        # Probe failed for an unrelated reason (no such container,
        # daemon error). Surface it as the exit code so the caller can
        # display the docker error rather than masking it with sh.
        log.warning(
            "container_shell probe of %s failed (exit %d): %s",
            name, probe.returncode, probe.stderr.strip(),
        )
        return probe.returncode

    def container_exec(
        self,
        name: str,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        argv = ["docker", "exec", name, *cmd]
        return self._run(argv, timeout=timeout)

    def container_inspect(self, name: str) -> dict:
        result = self._run(
            ["docker", "inspect", name],
            timeout=_HOST_INVENTORY_TIMEOUT,
        )
        if result.returncode != 0:
            log.debug("container_inspect failed for %s: %s", name, result.stderr.strip())
            return {}
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            log.warning("container_inspect could not parse output for %s", name)
            return {}
        if not isinstance(parsed, list) or not parsed:
            return {}
        first = parsed[0]
        return first if isinstance(first, dict) else {}
