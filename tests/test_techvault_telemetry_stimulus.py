"""TechVault freshness probes exercise real producers, never invented logs."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from aptl_techvault.evidence.techvault_telemetry_stimulus import (
    _SOURCES,
    emit_missing_agent_events,
)


class _Backend:
    def __init__(self) -> None:
        self.sizes = {(f"aptl-{node}", path): 10 for node, path in _SOURCES.items()}
        self.commands: list[tuple[str, tuple[str, ...]]] = []

    def container_exec(self, container, command, *, timeout=None):
        del timeout
        self.commands.append((container, tuple(command)))
        if command[:3] == ["stat", "-c", "%s"]:
            size = self.sizes.get((container, command[3]))
            return SimpleNamespace(
                returncode=0 if size is not None else 1, stdout=str(size)
            )
        if command[0] == "smbclient":
            node = "ad" if "//ad/sysvol" in command else "fileshare"
        elif command[0] == "curl":
            node = "webapp"
        else:
            node = container.removeprefix("aptl-")
        self.sizes[(f"aptl-{node}", _SOURCES[node])] += 1
        return SimpleNamespace(returncode=1 if node == "ad" else 0, stdout="")


def _realization():
    share = SimpleNamespace(name="Public", guest_ok=True)
    service = SimpleNamespace(shares=(share,))
    fileshare = SimpleNamespace(
        name="fileshare", runtime=SimpleNamespace(file_services=(service,))
    )
    return SimpleNamespace(nodes=(fileshare,))


def test_every_silent_agent_uses_a_native_producer_and_checks_its_declared_file(
    monkeypatch,
):
    from aptl_techvault.evidence import (
        techvault_telemetry_stimulus as telemetry_stimulus,
    )

    monkeypatch.setattr(
        telemetry_stimulus,
        "webapp_endpoint",
        lambda _realization: ("172.20.1.20", 8080),
    )
    backend = _Backend()
    declared = {node: (path,) for node, path in _SOURCES.items()}
    sqli_calls = []

    def trigger_sqli():
        sqli_calls.append(True)
        backend.sizes[("aptl-suricata", _SOURCES["suricata"])] += 1
        return {"trigger_id": "test"}

    assert emit_missing_agent_events(
        backend, _realization(), tuple(declared), declared, trigger_sqli
    )

    assert len(sqli_calls) == 1
    assert all(size > 10 for size in backend.sizes.values())
    assert not any(
        command[0] in {"touch", "tee", "sh", "bash"}
        for _container, command in backend.commands
    )
    assert any(
        command[:3] == ("smbclient", "-N", "-U") and "//ad/sysvol" in command
        for _container, command in backend.commands
    )


def test_a_missing_declared_source_cannot_be_stimulated(monkeypatch):
    from aptl_techvault.evidence import (
        techvault_telemetry_stimulus as telemetry_stimulus,
    )

    monkeypatch.setattr(
        telemetry_stimulus,
        "webapp_endpoint",
        lambda _realization: ("172.20.1.20", 8080),
    )
    backend = _Backend()

    assert not emit_missing_agent_events(
        backend, _realization(), ("dns",), {"dns": ()}, lambda: {"ok": True}
    )
    assert backend.commands == []


def test_stimulus_without_native_log_growth_does_not_count_as_telemetry(monkeypatch):
    from aptl_techvault.evidence import techvault_telemetry_stimulus

    monkeypatch.setattr(techvault_telemetry_stimulus.time, "sleep", lambda _s: None)

    class NoGrowthBackend(_Backend):
        def container_exec(self, container, command, *, timeout=None):
            if command[0] == "logger":
                self.commands.append((container, tuple(command)))
                return SimpleNamespace(returncode=0, stdout="")
            return super().container_exec(container, command, timeout=timeout)

    backend = NoGrowthBackend()

    assert not emit_missing_agent_events(
        backend,
        _realization(),
        ("victim",),
        {"victim": (_SOURCES["victim"],)},
        lambda: {"ok": True},
    )


def test_webapp_stimulus_requires_the_declared_endpoint(monkeypatch):
    from aptl_techvault.evidence import techvault_telemetry_stimulus

    monkeypatch.setattr(
        techvault_telemetry_stimulus, "webapp_endpoint", lambda _realization: None
    )
    backend = _Backend()

    assert not emit_missing_agent_events(
        backend,
        _realization(),
        ("webapp",),
        {"webapp": (_SOURCES["webapp"],)},
        lambda: {"ok": True},
    )
    assert not any(command[0] == "curl" for _container, command in backend.commands)


def test_native_owner_stimulates_only_silent_agents_and_waits_for_ingestion(
    monkeypatch,
):
    from aptl_techvault.evidence import techvault_native

    owner = object.__new__(techvault_native.TechVaultNativeEvidenceOwner)
    owner._backend = object()
    owner._realization = object()
    owner._project_dir = Path("/tmp/aptl-readiness-test")
    owner._now = lambda: "2026-01-01T00:00:01Z"
    sleeps = []
    owner._sleep = sleeps.append
    observations = iter(
        (
            {"hosts": [{"node_ref": "dns", "telemetry_fresh": False}]},
            {"hosts": [{"node_ref": "dns", "telemetry_fresh": True}]},
        )
    )
    monkeypatch.setattr(
        techvault_native, "wazuh_agent_readiness", lambda *_args: next(observations)
    )
    monkeypatch.setattr(
        techvault_native,
        "declared_endpoint_agents",
        lambda _realization: {"dns": ("techvault-dns-agent", (_SOURCES["dns"],))},
    )
    emitted = []
    monkeypatch.setattr(
        techvault_native,
        "emit_missing_agent_events",
        lambda _backend, _realization, missing, declared, _trigger: (
            emitted.append((missing, declared)) or True
        ),
    )

    result = owner.wazuh_agent_readiness_query(
        "2026-01-01T00:00:00Z", "2026-01-01T00:05:00Z"
    )

    assert result == {"hosts": [{"node_ref": "dns", "telemetry_fresh": True}]}
    assert emitted == [(["dns"], {"dns": (_SOURCES["dns"],)})]
    assert sleeps == [2.0]
