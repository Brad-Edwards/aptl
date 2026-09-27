"""Bounded adapter activity for TechVault's per-agent freshness demand.

Only the content-qualified adapter knows which real service action can cause
each declared source to produce a new record. These probes never append a
fabricated log line: each one exercises the service or syslog socket, verifies
its declared source grew, and leaves Wazuh attribution to the manager probe.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from urllib.parse import quote

from aptl_techvault.evidence.techvault_native_support import webapp_endpoint

_SAFE_SHARE = re.compile(r"[A-Za-z0-9_.-]+")
_SOURCES = {
    "ad": "/var/log/samba/log.samba",
    "db": "/var/log/postgresql/postgresql-15-main.log",
    "dns": "/var/log/named/query.log",
    "fileshare": "/var/log/samba/log.samba",
    "suricata": "/var/log/suricata/eve.json",
    "victim": "/var/log/secure",
    "webapp": "/var/log/gunicorn/access.log",
    "workstation": "/var/log/secure",
}


def _exec(backend: object, container: str, argv: list[str]) -> object | None:
    """Run a bounded guest probe without treating executor failure as success."""

    execute = getattr(backend, "container_exec", None)
    if not callable(execute):
        return None
    try:
        return execute(container, argv, timeout=30)
    except Exception:
        return None


def _size(backend: object, container: str, path: str) -> int | None:
    """Read the current size of a declared native log path."""

    result = _exec(backend, container, ["stat", "-c", "%s", path])
    if result is None or getattr(result, "returncode", 1) != 0:
        return None
    try:
        return max(0, int(str(getattr(result, "stdout", "")).strip()))
    except ValueError:
        return None


def _grew(backend: object, container: str, path: str, before: int) -> bool:
    """Wait for a fresh native event to increase the log size."""

    for attempt in range(21):
        current = _size(backend, container, path)
        if current is not None and current > before:
            return True
        if attempt < 20:
            time.sleep(0.5)
    return False


def _run(backend: object, container: str, argv: list[str]) -> bool:
    """Return whether one bounded guest action exited successfully."""

    result = _exec(backend, container, argv)
    return result is not None and getattr(result, "returncode", 1) == 0


def _guest_share(realization: object) -> str | None:
    """Select one admitted guest-readable share, not a guessed share name."""

    for node in getattr(realization, "nodes", ()) or ():
        if getattr(node, "name", None) != "fileshare":
            continue
        shares = [
            str(share.name)
            for service in getattr(getattr(node, "runtime", None), "file_services", ())
            or ()
            for share in getattr(service, "shares", ()) or ()
            if getattr(share, "guest_ok", False)
            and _SAFE_SHARE.fullmatch(str(getattr(share, "name", "")))
        ]
        return min(shares) if shares else None
    return None


def _stimulate(
    backend: object,
    realization: object,
    node: str,
    marker: str,
    trigger_sqli: Callable[[], Mapping[str, object] | None],
) -> bool:
    """Exercise the declared product source without fabricating log content."""

    emitted = False
    if node in {"victim", "workstation"}:
        emitted = _run(
            backend, f"aptl-{node}", ["logger", "-p", "authpriv.notice", marker]
        )
    elif node == "db":
        statement = f"DO $$ BEGIN RAISE LOG '{marker}'; END $$;"
        emitted = _run(
            backend,
            "aptl-db",
            ["runuser", "-u", "postgres", "--", "psql", "-Atqc", statement],
        )
    elif node == "dns":
        emitted = _run(
            backend,
            "aptl-dns",
            [
                "dig",
                "+time=2",
                "+tries=1",
                "@127.0.0.1",
                f"{marker}.techvault.local.",
                "A",
            ],
        )
    elif node == "fileshare":
        share = _guest_share(realization)
        emitted = bool(
            share
            and _run(
                backend,
                "aptl-kali",
                ["smbclient", "-N", f"//fileshare/{share}", "-c", "quit"],
            )
        )
    elif node == "ad":
        # Guest authorization is expected to fail; the audit log growth is
        # the proof of execution, not smbclient's exit status.
        emitted = (
            _exec(
                backend,
                "aptl-kali",
                ["smbclient", "-N", "-U", marker, "//ad/sysvol", "-c", "quit"],
            )
            is not None
        )
    elif node == "webapp":
        emitted = _stimulate_webapp(backend, realization, marker)
    elif node == "suricata":
        emitted = trigger_sqli() is not None
    return emitted


def _stimulate_webapp(backend: object, realization: object, marker: str) -> bool:
    """Exercise the SDL-declared in-world HTTP service from the Kali guest."""

    endpoint = webapp_endpoint(realization)
    if endpoint is None:
        return False
    address, port = endpoint
    return _run(
        backend,
        "aptl-kali",
        [
            "curl",
            "-fsS",
            "-o",
            "/dev/null",
            f"http://{address}:{port}/?aptl_readiness={quote(marker)}",
        ],
    )


def emit_missing_agent_events(
    backend: object,
    realization: object,
    missing: Sequence[str],
    declared_sources: Mapping[str, tuple[str, ...]],
    trigger_sqli: Callable[[], Mapping[str, object] | None],
) -> bool:
    """Stimulate only silent declared hosts and verify native source growth."""

    for node in sorted(set(missing)):
        if not _emit_declared_agent_event(
            backend, realization, node, declared_sources, trigger_sqli
        ):
            return False
    return True


def _emit_declared_agent_event(
    backend: object,
    realization: object,
    node: str,
    declared_sources: Mapping[str, tuple[str, ...]],
    trigger_sqli: Callable[[], Mapping[str, object] | None],
) -> bool:
    """Require one admitted source to grow after a real producer action."""

    path = _SOURCES.get(node)
    if path is None or path not in declared_sources.get(node, ()):
        return False
    container = f"aptl-{node}"
    before = _size(backend, container, path)
    if before is None:
        return False
    marker = f"aptl-readiness-{secrets.token_hex(8)}"
    return bool(
        _stimulate(backend, realization, node, marker, trigger_sqli)
        and _grew(backend, container, path, before)
    )


__all__ = ("emit_missing_agent_events",)
