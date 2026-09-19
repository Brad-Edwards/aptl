"""The released pack's log paths require working native producers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from raes.parser import parse_sdl_file

from aptl_techvault.log_sources import (
    _declared_tailed_files,
    _postgres_candidate,
    _rocky_syslog_candidate,
    _rocky_rsyslog_config,
    _samba_ad_candidate,
    _samba_ad_config,
    _samba_candidate,
    _samba_dropin,
    realize_log_sources,
)
from aptl_techvault.log_source_support import _postgres_cluster, _postgres_log_path
from tests.helpers import techvault_scenario_path


@pytest.fixture(scope="module")
def scenario(tmp_path_factory):
    return parse_sdl_file(
        techvault_scenario_path(tmp_path_factory.mktemp("techvault-log-contract"))
    )


def _node(scenario, name: str):
    return SimpleNamespace(
        container_name=f"aptl-{name}", runtime=scenario.nodes[name].runtime
    )


def test_only_declared_live_log_source_shapes_select_native_producers(scenario):
    selected = {}
    for name in ("ad", "db", "workstation", "fileshare", "victim", "misp"):
        runtime = scenario.nodes[name].runtime
        sources = _declared_tailed_files(runtime)
        selected[name] = (
            _postgres_candidate(runtime, sources),
            _rocky_syslog_candidate(runtime, sources),
            _samba_candidate(runtime, sources),
            _samba_ad_candidate(runtime, sources),
        )

    assert selected == {
        "ad": (False, False, False, True),
        "db": (True, False, False, False),
        "workstation": (False, True, False, False),
        "fileshare": (False, False, True, False),
        "victim": (False, True, False, False),
        "misp": (False, False, False, False),
    }


class _Backend:
    def __init__(self):
        self.commands: list[tuple[str, tuple[str, ...]]] = []
        self.payloads: list[str] = []
        self.pg_ready = False
        self.smb_probe = False

    def container_exec(self, name, cmd, *, timeout=None):
        del timeout
        self.commands.append((name, tuple(cmd)))
        if cmd[:2] == ["runuser", "-u"]:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "/var/log/postgresql\npostgresql-15-main.log\non\n"
                    if self.pg_ready
                    else "log\npostgresql-%Y-%m-%d.log\noff\n"
                ),
            )
        if cmd[:2] == ["pg_lsclusters", "--no-header"]:
            return SimpleNamespace(
                returncode=0, stdout="17 main 5432 online postgres\n"
            )
        if cmd[:1] == ["pg_ctlcluster"]:
            self.pg_ready = True
        if cmd[:1] == ["smbclient"]:
            self.smb_probe = True
        if cmd[:3] == ["stat", "-c", "%s"]:
            return SimpleNamespace(
                returncode=0 if self.smb_probe else 1,
                stdout="610\n" if self.smb_probe else "",
            )
        if cmd[:2] == ["cat", "/etc/rsyslog.conf"]:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    'module(load="imuxsock"\n'
                    '       SysSock.Use="off")\n'
                    'module(load="imjournal"\n'
                    '       StateFile="imjournal.state")\n'
                    '*.info action(type="omfile" file="/var/log/messages")\n'
                    'authpriv.* action(type="omfile" file="/var/log/secure")\n'
                ),
            )
        if cmd[:2] == ["readlink", "-f"]:
            return SimpleNamespace(returncode=1, stdout="")
        if cmd[:2] == ["test", "-L"]:
            return SimpleNamespace(returncode=1, stdout="")
        if cmd[:2] == [
            "sha256sum",
            "/etc/systemd/system/smbd.service.d/60-aptl-log-sources.conf",
        ]:
            return SimpleNamespace(returncode=1, stdout="")
        return SimpleNamespace(returncode=0, stdout="")

    def container_exec_with_input(self, name, cmd, payload, *, timeout=None):
        del timeout
        self.commands.append((name, tuple(cmd)))
        self.payloads.append(payload)
        return SimpleNamespace(returncode=0, stdout="")


def test_postgres_provider_configures_the_authored_path_not_the_package_version(
    scenario,
):
    backend = _Backend()

    assert realize_log_sources(backend, (_node(scenario, "db"),)) == []

    argvs = [cmd for _name, cmd in backend.commands]
    assert (
        "pg_conftool",
        "17",
        "main",
        "set",
        "log_filename",
        "postgresql-15-main.log",
    ) in argvs
    assert ("pg_ctlcluster", "17", "main", "restart") in argvs
    assert ("test", "-s", "/var/log/postgresql/postgresql-15-main.log") in argvs
    assert not any(cmd[:1] == ("touch",) for cmd in argvs)


@pytest.mark.parametrize(
    "sources",
    [
        frozenset(),
        frozenset({"/var/log/postgresql/../escaped.log"}),
        frozenset(
            {
                "/var/log/postgresql/first.log",
                "/var/log/postgresql/second.log",
            }
        ),
    ],
)
def test_postgres_provider_rejects_missing_or_ambiguous_authored_path(sources):
    path, reason = _postgres_log_path(sources)

    assert path is None
    assert reason is not None


@pytest.mark.parametrize(
    "row",
    [
        "17 main 5432 online postgres\n18 other 5432 online postgres\n",
        "17 ../other 5432 online postgres\n",
        "17 main;echo 5432 online postgres\n",
        "17\n",
    ],
)
def test_postgres_provider_rejects_ambiguous_or_unsafe_cluster_names(row):
    class ClusterBackend(_Backend):
        def container_exec(self, name, cmd, *, timeout=None):
            if cmd[:2] == ["pg_lsclusters", "--no-header"]:
                return SimpleNamespace(returncode=0, stdout=row)
            return super().container_exec(name, cmd, timeout=timeout)

    assert _postgres_cluster(ClusterBackend(), "aptl-db") is None


def test_rocky_provider_starts_rsyslog_and_proves_both_logs_receive_events(scenario):
    backend = _Backend()

    assert realize_log_sources(backend, (_node(scenario, "workstation"),)) == []

    argvs = [cmd for _name, cmd in backend.commands]
    assert ("test", "-x", "/usr/sbin/rsyslogd") in argvs
    assert not any(cmd[:2] == ("dnf", "install") for cmd in argvs)
    assert ("systemctl", "enable", "rsyslog.service") in argvs
    assert ("systemctl", "start", "rsyslog.service") in argvs
    assert ("systemctl", "is-active", "--quiet", "rsyslog.service") in argvs
    assert any(cmd[:3] == ("logger", "-p", "authpriv.notice") for cmd in argvs)
    assert any(cmd[:3] == ("logger", "-p", "user.notice") for cmd in argvs)
    assert ("systemctl", "start", "syslog.socket") in argvs
    assert (
        "ln",
        "-s",
        "/usr/lib/systemd/system/rsyslog.service",
        "/etc/systemd/system/syslog.service",
    ) in argvs
    assert ("systemctl", "restart", "systemd-journald.service") in argvs
    assert ("mkdir", "-p", "/run/aptl") in argvs
    assert ("rsyslogd", "-N1", "-f", "/run/aptl/rsyslog.conf") in argvs
    assert not any("/tmp/aptl-rsyslog.conf" in part for cmd in argvs for part in cmd)
    assert not any(cmd[:1] == ("touch",) for cmd in argvs)


def test_rocky_provider_uses_settled_unit_state_after_start_job_error(scenario):
    class TransientStartBackend(_Backend):
        def container_exec(self, name, cmd, *, timeout=None):
            result = super().container_exec(name, cmd, timeout=timeout)
            if cmd == ["systemctl", "start", "rsyslog.service"]:
                return SimpleNamespace(returncode=1, stdout="")
            return result

    backend = TransientStartBackend()

    assert realize_log_sources(backend, (_node(scenario, "victim"),)) == []
    assert (
        "aptl-victim",
        ("systemctl", "is-active", "--quiet", "rsyslog.service"),
    ) in backend.commands


def test_rocky_provider_rejects_a_service_that_never_becomes_active(
    scenario, monkeypatch
):
    from aptl_techvault import log_source_support

    monkeypatch.setattr(log_source_support.time, "sleep", lambda _seconds: None)

    class InactiveBackend(_Backend):
        def container_exec(self, name, cmd, *, timeout=None):
            result = super().container_exec(name, cmd, timeout=timeout)
            if cmd == ["systemctl", "is-active", "--quiet", "rsyslog.service"]:
                return SimpleNamespace(returncode=1, stdout="")
            return result

    backend = InactiveBackend()

    failures = realize_log_sources(backend, (_node(scenario, "victim"),))

    assert len(failures) == 1
    assert "rsyslog service did not start" in failures[0]


def test_rocky_provider_rejects_an_unexpected_syslog_service_alias(scenario):
    class WrongAliasBackend(_Backend):
        def container_exec(self, name, cmd, *, timeout=None):
            if cmd == ["test", "-L", "/etc/systemd/system/syslog.service"]:
                return SimpleNamespace(returncode=0, stdout="")
            if cmd == ["readlink", "-f", "/etc/systemd/system/syslog.service"]:
                return SimpleNamespace(returncode=0, stdout="/other/service\n")
            return super().container_exec(name, cmd, timeout=timeout)

    backend = WrongAliasBackend()

    failures = realize_log_sources(backend, (_node(scenario, "victim"),))

    assert len(failures) == 1
    assert "syslog socket service alias is unexpected" in failures[0]
    assert not any(
        cmd == ("systemctl", "daemon-reload") for _name, cmd in backend.commands
    )


def test_rhel_wazuh_base_installs_the_syslog_producer_before_network_isolation():
    dockerfile = (
        Path(__file__).resolve().parents[1]
        / "containers/generic-systemd-wazuh-agent-base/Dockerfile"
    ).read_text(encoding="utf-8")

    assert "dnf -y install rsyslog" in dockerfile


def test_rsyslog_adapter_replaces_the_broken_journal_input_not_the_output_rules():
    original = (
        'module(load="imuxsock"\n'
        '       SysSock.Use="off")\n'
        'module(load="imjournal"\n'
        '       StateFile="imjournal.state")\n'
        '*.info action(type="omfile" file="/var/log/messages")\n'
        'authpriv.* action(type="omfile" file="/var/log/secure")\n'
    )

    transformed = _rocky_rsyslog_config(original)

    assert transformed is not None
    assert 'module(load="imuxsock" SysSock.Use="on")' in transformed
    assert 'module(load="imjournal"' not in transformed
    assert 'file="/var/log/secure"' in transformed


def test_samba_provider_preserves_exact_pack_config_and_uses_native_audit_class(
    scenario,
):
    backend = _Backend()

    assert (
        realize_log_sources(
            backend, (_node(scenario, "fileshare"), _node(scenario, "kali"))
        )
        == []
    )

    assert backend.payloads == [_samba_dropin()]
    payload = backend.payloads[0]
    assert "--option=log file=/var/log/samba/log.smbd" in payload
    assert "auth_audit:5@/var/log/samba/log.samba" in payload
    assert "/etc/samba/smb.conf" not in payload
    argvs = [cmd for _name, cmd in backend.commands]
    assert ("systemctl", "restart", "smbd.service") in argvs
    assert (
        "smbclient",
        "-N",
        "//fileshare/Public",
        "-c",
        "quit",
    ) in argvs
    assert ("stat", "-c", "%s", "/var/log/samba/log.samba") in argvs
    assert not any(cmd[:1] == ("touch",) for cmd in argvs)


def test_samba_provider_rejects_a_failed_service_override_write(scenario):
    class FailedOverrideBackend(_Backend):
        def container_exec_with_input(self, name, cmd, payload, *, timeout=None):
            super().container_exec_with_input(name, cmd, payload, timeout=timeout)
            return SimpleNamespace(returncode=1, stdout="")

    backend = FailedOverrideBackend()

    failures = realize_log_sources(
        backend, (_node(scenario, "fileshare"), _node(scenario, "kali"))
    )

    assert len(failures) == 1
    assert "Samba service override failed" in failures[0]
    assert not any(
        cmd[:2] == ("systemctl", "restart") for _name, cmd in backend.commands
    )


def test_domain_samba_config_is_idempotent_and_rejects_conflicting_log_authority():
    original = "# Global parameters\n[global]\n\trealm = TECHVAULT.LOCAL\n\n[sysvol]\n\tpath = /var/lib/samba/sysvol\n"

    configured = _samba_ad_config(original)

    assert configured is not None
    assert "\tlog file = /var/log/samba/log.samba\n" in configured
    assert "\tlog level = 1 auth_audit:5\n" in configured
    assert _samba_ad_config(configured) == configured
    assert (
        _samba_ad_config(original.replace("[global]\n", "[global]\n\tlog level = 9\n"))
        is None
    )
    assert (
        _samba_ad_config(
            original.replace(
                "[global]\n",
                "[global]\n\tlog level = 1 auth_audit:5\n\tlog level = 1 auth_audit:5\n",
            )
        )
        is None
    )


def test_domain_samba_provider_proves_a_new_native_audit_event(scenario):
    class DomainBackend(_Backend):
        def __init__(self):
            super().__init__()
            self.config = "[global]\n\trealm = TECHVAULT.LOCAL\n\n[sysvol]\n\tpath = /var/lib/samba/sysvol\n"
            self.audit_size = 100

        def container_exec(self, name, cmd, *, timeout=None):
            if cmd[:1] == ["cat"] and cmd[1] in {
                "/etc/samba/smb.conf",
                "/var/lib/samba/smb.conf.provisioned",
            }:
                self.commands.append((name, tuple(cmd)))
                return SimpleNamespace(returncode=0, stdout=self.config)
            if cmd[:3] == ["stat", "-c", "%s"]:
                self.commands.append((name, tuple(cmd)))
                return SimpleNamespace(returncode=0, stdout=f"{self.audit_size}\n")
            if cmd[:1] == ["smbclient"]:
                self.commands.append((name, tuple(cmd)))
                self.audit_size += 100
                return SimpleNamespace(returncode=1, stdout="")
            return super().container_exec(name, cmd, timeout=timeout)

    backend = DomainBackend()

    assert (
        realize_log_sources(backend, (_node(scenario, "ad"), _node(scenario, "kali")))
        == []
    )
    assert len(backend.payloads) == 2
    assert all("log level = 1 auth_audit:5" in payload for payload in backend.payloads)
    assert ("aptl-ad", ("smbcontrol", "all", "reload-config")) in backend.commands
    assert any(
        cmd[:3] == ("smbclient", "-N", "-U")
        and cmd[4:] == ("//ad/sysvol", "-c", "quit")
        for _, cmd in backend.commands
    )
