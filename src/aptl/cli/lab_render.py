"""Rendering helpers for lab lifecycle CLI output."""

from pathlib import Path

import typer

from aptl.core.host_ports import ResolvedPort
from aptl.core.lab import LabResult
from aptl.core.lab_types import StartupDiagnostic, StartupOutcome

# Service (compose name) -> its default host port. Used to look up the actual
# published port from a lab-start resolution so the access summary always shows
# where a service really is, even after an in-use default was remapped.
_WAZUH_DASHBOARD_SVC = "wazuh.dashboard"
_GRAFANA_SVC = "aptl-grafana-otel"
_REVERSE_SVC = "reverse"
_WAZUH_DASHBOARD_DEFAULT = 443
_GRAFANA_DEFAULT = 3100
_REVERSE_DEFAULT = 2027

# SOC services whose MCP server config (mcp/<name>/docker-lab-config.json)
# hardcodes the host port on localhost. If one of these is remapped, the MCP
# server config still points at the default port, so flag it for the operator.
_MCP_BACKED_SERVICES = {
    "wazuh.indexer",
    "wazuh.manager",
    "thehive",
    "misp",
    "shuffle-frontend",
    "kali-ssh-proxy",
}


# Headline phrasing per outcome. Values are the same stable wire strings as the
# StartupOutcome enum so an operator (or a parser) can grep for them.
_OUTCOME_HEADLINES: dict[StartupOutcome, str] = {
    StartupOutcome.READY: "Lab is ready.",
    StartupOutcome.DEGRADED_USABLE: (
        "Lab is degraded_usable - telemetry/cosmetic warnings, scenarios "
        "should still run."
    ),
    StartupOutcome.DEGRADED_UNUSABLE: (
        "Lab is degraded_unusable - some capabilities or SSH targets are not reachable."
    ),
    StartupOutcome.FAILED: "Lab start failed.",
}


def render_start_result(result: LabResult) -> None:
    """Print a structured summary of a lab-start result."""
    typer.echo(_OUTCOME_HEADLINES[result.outcome])
    if result.outcome is StartupOutcome.FAILED and result.error:
        typer.echo(f"  error: {result.error}")
    if not result.diagnostics:
        return
    typer.echo(f"  diagnostics ({len(result.diagnostics)}):")
    impacts_in_order = ["readiness", "capability", "telemetry", "cosmetic"]
    grouped: dict[str, list[StartupDiagnostic]] = {}
    for diag in result.diagnostics:
        grouped.setdefault(diag.impact.value, []).append(diag)
    for impact in impacts_in_order:
        for diag in grouped.get(impact, []):
            label = f"{diag.step}/{diag.component}" if diag.component else diag.step
            typer.echo(
                f"    [{diag.impact.value}|{diag.severity.value}] "
                f"{label} - {diag.message}"
            )
            if diag.operator_action:
                typer.echo(f"      action: {diag.operator_action}")


def _resolved_port(
    resolved_ports: list[ResolvedPort], service: str, default: int
) -> int:
    """Return the actual published host port for *service* (default if unknown)."""
    for entry in resolved_ports or ():
        if getattr(entry, "service", None) == service:
            return getattr(entry, "resolved_port", default)
    return default


def _cli_backend(project_dir: Path):
    """Resolve the deployment backend for a CLI query, or None on any failure.

    Best-effort: a missing/invalid project config must not abort the command.
    """
    try:
        from aptl.cli._common import resolve_config_for_cli
        from aptl.core.deployment import get_backend

        config, project_root = resolve_config_for_cli(project_dir)
        return get_backend(config, project_root)
    except Exception:
        return None


def _binding_to_resolved_port(
    service: str, default_port: int, proto: str, binding: dict
) -> ResolvedPort | None:
    """Turn one docker port binding into a ResolvedPort, or None if unusable."""
    try:
        host_port = int(binding.get("HostPort", 0))
    except (TypeError, ValueError):
        return None
    if host_port == 0:
        return None
    return ResolvedPort(
        service=service,
        env_var=None,
        default_port=default_port,
        resolved_port=host_port,
        protos=(proto or "tcp",),
        host_ip=binding.get("HostIp"),
        remapped=(host_port != default_port),
    )


def _container_resolved_ports(backend, name: str, service: str) -> list[ResolvedPort]:
    """Return the published ResolvedPorts for one running container."""
    try:
        info = backend.container_inspect(name)
    except Exception:
        return []
    ports = (info.get("NetworkSettings") or {}).get("Ports") or {}
    if not isinstance(ports, dict):
        return []
    resolved: list[ResolvedPort] = []
    for container_port_proto, bindings in ports.items():
        container_port_str, _, proto = container_port_proto.partition("/")
        try:
            default_port = int(container_port_str)
        except ValueError:
            continue
        for binding in bindings or ():
            entry = _binding_to_resolved_port(service, default_port, proto, binding)
            if entry is not None:
                resolved.append(entry)
    return resolved


def live_resolved_ports(project_dir: Path) -> list[ResolvedPort]:
    """Reconstruct a ResolvedPort list from docker's runtime state.

    `_emit_lab_access_summary` needs a ResolvedPort list to print live URLs;
    `lab start` passes the one it computed at port-resolution time. Later
    commands (`aptl lab info`) run against a running lab and have to ask
    docker what actually got published — otherwise the URLs default to the
    compile-time constants, and any host with a taken default port (Cursor's
    tunnels, k8s port-forward, AirPlay on 3100, etc.) sees a URL that goes to
    the wrong service (#737).

    Best-effort: any failure returns an empty list and the caller falls back
    to the compile-time defaults.
    """
    backend = _cli_backend(project_dir)
    if backend is None:
        return []
    try:
        containers = backend.container_list(all_containers=False)
    except Exception:
        return []
    resolved: list[ResolvedPort] = []
    for entry in containers:
        service = entry.get("Service") or ""
        name = (entry.get("Name") or "").lstrip("/")
        if service and name:
            resolved.extend(_container_resolved_ports(backend, name, service))
    return resolved


def _emit_host_port_remaps(resolved_ports: list[ResolvedPort]) -> None:
    """List any ports that were remapped off an in-use default."""
    remapped = [r for r in (resolved_ports or ()) if getattr(r, "remapped", False)]
    if not remapped:
        return
    typer.echo("")
    typer.echo(
        "Host port remaps (a default was already in use on this host, so the "
        "service is published on a free port instead):"
    )
    mcp_affected = []
    for entry in sorted(remapped, key=lambda r: r.service):
        protos = "/".join(entry.protos)
        typer.echo(
            f"  {entry.service}: {entry.default_port} -> "
            f"{entry.resolved_port} ({protos})"
        )
        if entry.service in _MCP_BACKED_SERVICES:
            mcp_affected.append(entry)
    if mcp_affected:
        typer.echo("")
        typer.echo(
            "  Note: these services are consumed by MCP servers that pin the "
            "default host port in mcp/<name>/docker-lab-config.json. If you "
            "use those MCP servers, point them at the remapped port above (or "
            "free the default port and restart)."
        )


def emit_lab_access_summary(
    project_dir: Path, resolved_ports: list[ResolvedPort] | None = None
) -> None:
    """Print the credential locations and common lab entry points.

    ``resolved_ports`` (host_ports.ResolvedPort list from a lab-start run) makes
    the printed URLs reflect the real published ports — important on hosts where
    a default port was in use and the service was remapped to a free one.
    """
    resolved_ports = resolved_ports or []
    env_path = project_dir / ".env"
    dashboard_port = _resolved_port(
        resolved_ports, _WAZUH_DASHBOARD_SVC, _WAZUH_DASHBOARD_DEFAULT
    )
    grafana_port = _resolved_port(resolved_ports, _GRAFANA_SVC, _GRAFANA_DEFAULT)
    reverse_port = _resolved_port(resolved_ports, _REVERSE_SVC, _REVERSE_DEFAULT)
    typer.echo("")
    typer.echo(f"Credentials file: {env_path}")
    typer.echo(
        "Keep this file for this temporary range; remove it before a fresh "
        "credential reset."
    )
    typer.echo("")
    typer.echo("Access:")
    typer.echo(f"  Wazuh Dashboard: https://localhost:{dashboard_port}")
    typer.echo("    username: admin")
    typer.echo("    password: see INDEXER_PASSWORD in .env")
    typer.echo(f"  Grafana: http://localhost:{grafana_port}")
    typer.echo("    username: admin")
    typer.echo("    password: see GRAFANA_ADMIN_PASSWORD in .env")
    typer.echo("  Reverse engineering SSH:")
    typer.echo(f"    ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p {reverse_port}")
    _emit_host_port_remaps(resolved_ports)
