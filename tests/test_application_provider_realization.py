"""Backend-selected application provider realization tests."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from aptl.core.deployment._application_provider_realization import (
    realize_application_providers,
)
from aptl.core.deployment._proc_net_listeners import ContainerListeners


class _Backend:
    def __init__(self, *, becomes_ready: bool = True):
        self.started: list[tuple[str, list[str]]] = []
        self.becomes_ready = becomes_ready

    def container_exec_detached(self, name, cmd, *, timeout=None):
        self.started.append((name, cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def observe_container_listeners(self, _name):
        ready = bool(self.started) and self.becomes_ready
        return ContainerListeners(sockets=(("tcp", "0.0.0.0", 8080),) if ready else ())


def _node():
    return SimpleNamespace(
        backend_provider_kind="python-flask-application",
        backend_provider_parameters=(
            ("application_id", "portal"),
            ("module", "app:app"),
            ("port", "8080"),
            ("workdir", "/app"),
        ),
        container_name="aptl-webapp",
    )


def test_flask_provider_starts_gunicorn_and_requires_native_listener_readback():
    backend = _Backend()

    assert realize_application_providers(backend, (_node(),)) == []

    container, command = backend.started[0]
    assert container == "aptl-webapp"
    assert command == [
        "/usr/bin/python3",
        "-m",
        "gunicorn",
        "--chdir",
        "/app",
        "--bind",
        "0.0.0.0:8080",
        "--access-logfile",
        "/var/log/gunicorn/access.log",
        "--error-logfile",
        "/var/log/gunicorn/error.log",
        "app:app",
    ]


def test_flask_provider_fails_when_listener_never_appears(monkeypatch):
    monkeypatch.setattr(
        "aptl.core.deployment._application_provider_realization.time.sleep",
        lambda _seconds: None,
    )

    assert realize_application_providers(_Backend(becomes_ready=False), (_node(),)) == [
        "Flask application provider failed for aptl-webapp"
    ]
