"""Start and verify backend-selected application providers."""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Protocol

from aptl.core.deployment._proc_net_listeners import ContainerListeners


class ApplicationProviderBackend(Protocol):
    """Narrow backend surface required by application providers."""

    def container_exec_detached(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> object: ...

    def observe_container_listeners(self, name: str) -> ContainerListeners | None: ...


def realize_application_providers(
    backend: ApplicationProviderBackend, nodes: Iterable[object]
) -> list[str]:
    """Start every selected application provider and return bounded failures."""

    failures: list[str] = []
    for node in nodes:
        if getattr(node, "backend_provider_kind", "") != "python-flask-application":
            continue
        container = str(getattr(node, "container_name", "") or "")
        parameters = dict(getattr(node, "backend_provider_parameters", ()))
        try:
            port = int(parameters.get("port", ""))
        except ValueError:
            port = 0
        if not container or not 0 < port <= 65535:
            failures.append("Flask provider has invalid realization parameters")
            continue
        if _listener_ready(backend, container, port):
            continue
        command = [
            "/usr/bin/python3",
            "-m",
            "gunicorn",
            "--chdir",
            parameters.get("workdir", "/app"),
            "--bind",
            f"0.0.0.0:{port}",
            "--access-logfile",
            "/var/log/gunicorn/access.log",
            "--error-logfile",
            "/var/log/gunicorn/error.log",
            parameters.get("module", "app:app"),
        ]
        started = backend.container_exec_detached(container, command, timeout=30)
        if getattr(started, "returncode", 1) != 0 or not _await_listener(
            backend, container, port
        ):
            failures.append(f"Flask application provider failed for {container}")
    return failures


def _await_listener(
    backend: ApplicationProviderBackend, container: str, port: int
) -> bool:
    """Wait briefly for the selected application provider to bind its port."""

    for _attempt in range(50):
        if _listener_ready(backend, container, port):
            return True
        time.sleep(0.2)
    return False


def _listener_ready(
    backend: ApplicationProviderBackend, container: str, port: int
) -> bool:
    """Return whether native listener readback sees the provider's TCP port."""

    observed = backend.observe_container_listeners(container)
    return bool(
        observed is not None
        and any(
            protocol == "tcp" and candidate == port
            for protocol, _address, candidate in observed.sockets
        )
    )


__all__ = ("realize_application_providers",)
