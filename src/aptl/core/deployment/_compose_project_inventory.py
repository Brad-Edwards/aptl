"""Checked all-state container inventory for one Docker project."""

from __future__ import annotations

import re
from typing import Any

from aptl.core.deployment.errors import BackendObservationError, BackendTimeoutError
from aptl.core.lab_types import LabStatus
from aptl.utils.redaction import redact

_HOST_INVENTORY_TIMEOUT = 90
_PROJECT_OWNERSHIP_LABELS = (
    "com.docker.compose.project",
    "aptl.lifecycle.project",
)
_MAX_INVENTORY_ERROR_LENGTH = 512


def _parse_labels(labels_str: str) -> dict[str, str]:
    """Parse a comma-separated ``k=v,k=v`` labels string from ``docker ps``."""

    if not labels_str:
        return {}
    out: dict[str, str] = {}
    for pair in labels_str.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def _parse_ports(ports_str: str) -> list[str]:
    """Parse a comma-separated ports string from ``docker ps``."""

    if not ports_str:
        return []
    return [port.strip() for port in ports_str.split(",") if port.strip()]


def _parse_lab_row(line: str) -> dict[str, Any] | None:
    """Parse one project-inventory TSV row, or reject a malformed row."""

    parts = line.split("\t", 6)
    if len(parts) < 6:
        return None
    health_match = re.search(
        r"\((healthy|unhealthy|health: starting)\)", parts[3], re.IGNORECASE
    )
    health = health_match.group(1).casefold() if health_match else ""
    if health == "health: starting":
        health = "starting"
    return {
        "name": parts[0],
        "image": parts[1],
        "id": parts[2],
        "status": parts[3],
        "state": parts[4],
        "health": health,
        "labels": _parse_labels(parts[5]),
        "ports": _parse_ports(parts[6] if len(parts) > 6 else ""),
    }


def _bounded_inventory_error(stderr: str) -> str:
    """Return a redacted, bounded backend error for the public status envelope."""

    safe = str(redact(stderr)).strip()
    return (safe or "container inventory command failed")[:_MAX_INVENTORY_ERROR_LENGTH]


class ComposeProjectInventoryMixin(object):
    """Project-owned inventory methods shared by local and SSH backends."""

    def _project_container_status(self) -> LabStatus:
        """Return checked, all-state inventory for the configured project."""

        fmt = (
            "{{.Names}}\t{{.Image}}\t{{.ID}}\t{{.Status}}\t{{.State}}\t"
            "{{.Labels}}\t{{.Ports}}"
        )
        by_id: dict[str, dict[str, Any]] = {}
        failure: str | None = None
        for label in _PROJECT_OWNERSHIP_LABELS:
            try:
                result = self._run(
                    [
                        "docker",
                        "ps",
                        "-a",
                        "--filter",
                        f"label={label}={self._project_name}",
                        "--format",
                        fmt,
                    ],
                    timeout=_HOST_INVENTORY_TIMEOUT,
                )
            except (BackendTimeoutError, OSError):
                failure = "Project container inventory could not be observed"
            else:
                if result.returncode != 0:
                    failure = _bounded_inventory_error(result.stderr)
                else:
                    for line in result.stdout.splitlines():
                        if not line.strip():
                            continue
                        row = _parse_lab_row(line)
                        if row is None or not row["id"]:
                            failure = "Failed to parse project container inventory"
                            break
                        by_id.setdefault(row["id"], row)
            if failure is not None:
                break

        if failure is not None:
            return LabStatus(running=False, error=failure)
        containers = sorted(by_id.values(), key=lambda row: (row["name"], row["id"]))
        return LabStatus(
            running=any(
                str(container.get("state", "")).casefold() == "running"
                for container in containers
            ),
            containers=containers,
        )

    def host_list_lab_containers(self) -> list[dict[str, Any]]:
        """Return all-state project inventory for snapshot/readback callers.

        Raises :class:`BackendObservationError` when the shared checked query
        cannot prove the inventory, so snapshot and boundary consumers never
        collapse a failed observation into an apparently valid empty project.
        """

        status = self._project_container_status()
        if status.error:
            raise BackendObservationError(status.error)
        return status.containers
