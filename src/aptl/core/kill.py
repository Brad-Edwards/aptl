"""Emergency kill switch for all agent and MCP operations.

Discovers and terminates MCP server processes, optionally stops lab
containers, clears scenario session state, and cleans up trace context
files. Designed for resilience: each step runs independently so that a
failure in one does not prevent the others.
"""

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from aptl.core.lab import ALL_KNOWN_PROFILES, build_compose_command
from aptl.core.session import ScenarioSession
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("kill")

MCP_SERVER_NAMES = [
    "mcp-wazuh",
    "mcp-red",
    "mcp-reverse",
    "mcp-soar",
    "mcp-indexer",
    "mcp-casemgmt",
    "mcp-network",
    "mcp-threatintel",
]

_TRACE_CONTEXT_FILENAME = "trace-context.json"

# Timeout for Docker Compose subprocess calls (seconds).  Generous
# enough for a large stack, short enough that a hung daemon won't
# block the kill switch indefinitely.
_DOCKER_TIMEOUT = 30


@dataclass
class KillResult:
    """Result of the kill switch operation."""

    success: bool
    mcp_processes_killed: int = 0
    containers_stopped: bool = False
    session_cleared: bool = False
    trace_context_cleaned: bool = False
    errors: list[str] = field(default_factory=list)


def find_mcp_processes() -> list[dict]:
    """Discover running MCP server Node.js processes.

    Scans ``/proc/*/cmdline`` on Linux for processes whose command line
    contains a known MCP server build path (e.g. ``mcp-wazuh/build/index.js``).
    Falls back to ``pgrep -f`` on non-Linux platforms.

    Returns:
        List of dicts with keys ``pid`` (int), ``cmdline`` (str), and
        ``name`` (str, the matched server name).
    """
    if sys.platform == "linux":
        return _find_via_proc()
    return _find_via_pgrep()


def _find_via_proc() -> list[dict]:
    """Scan /proc for MCP server processes.

    Skips the current process to avoid false-positive matches when the
    kill switch's own command line happens to contain an MCP server name
    (e.g. in log messages or grep patterns).
    """
    found: list[dict] = []
    own_pid = os.getpid()
    try:
        entries = os.listdir("/proc")
    except OSError:
        log.warning("Cannot read /proc, falling back to pgrep")
        return _find_via_pgrep()

    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == own_pid:
            continue
        cmdline_path = f"/proc/{pid}/cmdline"
        try:
            with open(cmdline_path, "rb") as f:
                raw = f.read()
        except (OSError, PermissionError):
            continue

        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        for name in MCP_SERVER_NAMES:
            if f"{name}/build/index.js" in cmdline:
                found.append({"pid": pid, "cmdline": cmdline, "name": name})
                break

    return found


def _find_via_pgrep() -> list[dict]:
    """Discover MCP processes using pgrep (non-Linux fallback)."""
    found: list[dict] = []
    for name in MCP_SERVER_NAMES:
        pattern = f"{name}/build/index.js"
        try:
            result = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    pid = int(line.strip())
                    found.append({"pid": pid, "cmdline": pattern, "name": name})
        except (FileNotFoundError, OSError, ValueError):
            continue
    return found


def _process_exited(pid: int) -> bool:
    """Check whether a process has exited.

    Uses ``os.kill(pid, 0)`` which sends no signal but checks existence.
    Returns True if the process is gone (``ProcessLookupError``) or if
    we lack permission to signal it (``PermissionError``).  In the
    permission case the process may still be alive, but since we also
    cannot SIGKILL it there is no point waiting further.
    """
    try:
        os.kill(pid, 0)
        return False
    except (ProcessLookupError, PermissionError):
        return True


def kill_mcp_processes(timeout: float = 5.0) -> tuple[int, list[str]]:
    """Terminate all running MCP server processes.

    Sends SIGTERM first, waits up to *timeout* seconds for graceful
    shutdown (allowing OTel span flush), then sends SIGKILL to any
    survivors.

    Args:
        timeout: Seconds to wait after SIGTERM before sending SIGKILL.

    Returns:
        Tuple of (number of processes killed, list of error messages).
    """
    processes = find_mcp_processes()
    if not processes:
        log.info("No MCP server processes found")
        return 0, []

    log.info("Found %d MCP server process(es): %s", len(processes),
             ", ".join(f"{p['name']}(pid={p['pid']})" for p in processes))

    errors: list[str] = []
    pids_to_track: list[int] = []

    # Phase 1: SIGTERM
    for proc in processes:
        pid = proc["pid"]
        try:
            os.kill(pid, signal.SIGTERM)
            pids_to_track.append(pid)
            log.info("Sent SIGTERM to %s (pid=%d)", proc["name"], pid)
        except ProcessLookupError:
            log.debug("Process %d already dead", pid)
        except PermissionError:
            errors.append(f"Permission denied killing {proc['name']} (pid={pid})")
            log.warning("Permission denied sending SIGTERM to pid=%d", pid)

    # Phase 2: Wait for graceful shutdown
    deadline = time.monotonic() + timeout
    while pids_to_track and time.monotonic() < deadline:
        pids_to_track = [pid for pid in pids_to_track if not _process_exited(pid)]
        if pids_to_track:
            time.sleep(0.25)

    # Phase 3: SIGKILL survivors
    for pid in pids_to_track:
        try:
            os.kill(pid, signal.SIGKILL)
            log.warning("Sent SIGKILL to pid=%d (did not exit after SIGTERM)", pid)
        except ProcessLookupError:
            pass
        except PermissionError:
            errors.append(f"Permission denied force-killing pid={pid}")

    killed = len(processes) - len(errors)
    log.info("Killed %d MCP server process(es)", killed)
    return killed, errors


def kill_lab_containers(
    project_dir: Optional[Path] = None,
    backend: Optional["DeploymentBackend"] = None,
) -> tuple[bool, str]:
    """Emergency-stop all lab containers.

    Uses the deployment backend's kill method for immediate shutdown.
    Falls back to direct Docker Compose subprocess calls if no backend
    is provided.

    Args:
        project_dir: Working directory for Docker Compose.
        backend: Optional pre-created deployment backend.

    Returns:
        Tuple of (success, error_message).
    """
    profiles = list(ALL_KNOWN_PROFILES)

    if backend is not None:
        return backend.kill(profiles)

    # Fallback: direct Docker Compose calls (for backward compat and
    # cases where config is unavailable)
    kwargs: dict = {"capture_output": True, "text": True, "timeout": _DOCKER_TIMEOUT}
    if project_dir is not None:
        kwargs["cwd"] = project_dir

    # Phase 1: docker compose kill (immediate SIGKILL)
    kill_cmd = ["docker", "compose"]
    for profile in profiles:
        kill_cmd.extend(["--profile", profile])
    kill_cmd.append("kill")

    log.info("Running: %s", " ".join(kill_cmd))
    kill_ok = False
    try:
        result = subprocess.run(kill_cmd, **kwargs)
        kill_ok = result.returncode == 0
        if not kill_ok:
            log.warning("docker compose kill stderr: %s", result.stderr.strip())
    except subprocess.TimeoutExpired:
        log.warning("docker compose kill timed out after %ds", _DOCKER_TIMEOUT)
    except (FileNotFoundError, OSError) as exc:
        msg = f"docker compose kill failed: {exc}"
        log.error(msg)
        return False, msg

    # Phase 2: docker compose down (cleanup).  Treat non-zero exit as
    # a warning — the important work (SIGKILL) already happened above.
    down_cmd = build_compose_command("down", profiles=profiles)
    log.info("Running: %s", " ".join(down_cmd))
    try:
        result = subprocess.run(down_cmd, **kwargs)
        if result.returncode != 0:
            log.warning("docker compose down stderr: %s", result.stderr.strip())
    except subprocess.TimeoutExpired:
        log.warning("docker compose down timed out after %ds", _DOCKER_TIMEOUT)
    except (FileNotFoundError, OSError) as exc:
        log.warning("docker compose down failed: %s", exc)

    if not kill_ok:
        return False, "docker compose kill returned non-zero"

    log.info("All lab containers stopped")
    return True, ""


def clear_session(state_dir: Path) -> bool:
    """Clear any active scenario session.

    Args:
        state_dir: Path to the ``.aptl/`` state directory.

    Returns:
        True if a session was cleared, False if none existed.
    """
    session_mgr = ScenarioSession(state_dir)
    active = session_mgr.get_active()
    if active is None:
        log.debug("No active session to clear")
        return False

    log.info("Clearing active session for scenario '%s'", active.scenario_id)
    session_mgr.clear()
    return True


def clean_trace_context(state_dir: Path) -> bool:
    """Remove the trace context file if it exists.

    Args:
        state_dir: Path to the ``.aptl/`` state directory.

    Returns:
        True if the file was removed, False if it did not exist.
    """
    trace_file = state_dir / _TRACE_CONTEXT_FILENAME
    if trace_file.exists():
        trace_file.unlink()
        log.info("Removed trace context file: %s", trace_file)
        return True
    log.debug("No trace context file at %s", trace_file)
    return False


def execute_kill(
    containers: bool = False,
    project_dir: Optional[Path] = None,
) -> KillResult:
    """Execute the emergency kill switch.

    Runs each step independently so that a failure in one does not
    prevent the others from executing.

    Args:
        containers: If True, also force-stop all lab containers.
        project_dir: APTL project directory (defaults to cwd).

    Returns:
        KillResult with details of what was done.
    """
    resolved_dir = Path(project_dir) if project_dir else Path(".")
    state_dir = resolved_dir / ".aptl"
    errors: list[str] = []

    # Step 1: Kill MCP processes (highest priority)
    mcp_killed = 0
    try:
        mcp_killed, mcp_errors = kill_mcp_processes()
        errors.extend(mcp_errors)
    except Exception as exc:
        msg = f"MCP process kill failed: {exc}"
        log.error(msg)
        errors.append(msg)

    # Step 2: Kill lab containers (if requested)
    containers_stopped = False
    if containers:
        try:
            containers_stopped, container_error = kill_lab_containers(
                project_dir=resolved_dir,
            )
            if container_error:
                errors.append(container_error)
        except Exception as exc:
            msg = f"Container kill failed: {exc}"
            log.error(msg)
            errors.append(msg)

    # Step 3: Clear session state
    session_cleared = False
    try:
        session_cleared = clear_session(state_dir)
    except Exception as exc:
        msg = f"Session clear failed: {exc}"
        log.error(msg)
        errors.append(msg)

    # Step 4: Clean up trace context
    trace_cleaned = False
    try:
        trace_cleaned = clean_trace_context(state_dir)
    except Exception as exc:
        msg = f"Trace context cleanup failed: {exc}"
        log.error(msg)
        errors.append(msg)

    # Success if any step accomplished something, or if there was simply
    # nothing to kill (no errors).
    any_action = mcp_killed > 0 or containers_stopped or session_cleared or trace_cleaned
    success = any_action or len(errors) == 0

    result = KillResult(
        success=success,
        mcp_processes_killed=mcp_killed,
        containers_stopped=containers_stopped,
        session_cleared=session_cleared,
        trace_context_cleaned=trace_cleaned,
        errors=errors,
    )

    log.info(
        "Kill switch complete: mcp=%d containers=%s session=%s trace=%s errors=%d",
        mcp_killed, containers_stopped, session_cleared, trace_cleaned, len(errors),
    )
    return result
