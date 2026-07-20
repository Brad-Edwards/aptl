"""Tests for the concrete Docker materialization executor (ADR-048).

The executor implements the generic `MaterializationExecutor` surface by running
generic OS commands (package manager, `groupadd`/`useradd`/`getent`/`id`,
`systemctl`) inside a node's base-OS container via an injected exec callable. It
is product-agnostic: dispatch never depends on any node or product name. Tests
drive it with a fake exec that records commands and returns canned outcomes, so
no Docker daemon is needed.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aptl.backends.aces_docker_materializer import (
    DockerMaterializationExecutor,
    MaterializationCommandError,
)
from aptl.backends.aces_materializer import EnsureDirectoryOp, EnsureUserOp


class _FakeExec:
    def __init__(self, responder=None) -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self._responder = responder or (lambda container, argv: (0, ""))

    def __call__(self, container: str, argv: list[str]):
        self.calls.append((container, argv))
        code, out = self._responder(container, argv)
        return SimpleNamespace(returncode=code, stdout=out)

    def argvs(self) -> list[list[str]]:
        return [argv for _, argv in self.calls]


def _executor(exec_fn, *, started=None):
    def start_base(addr, image):
        if started is not None:
            started.append((addr, image))

    return DockerMaterializationExecutor(
        run=exec_fn,
        container_for=lambda addr: "aptl-" + addr.rsplit(".", 1)[-1],
        start_base=start_base,
    )


class TestBaseSubstrate:
    def test_ensure_base_substrate_starts_the_base_container(self):
        started: list[tuple[str, str]] = []
        ex = _executor(_FakeExec(), started=started)
        ex.ensure_base_substrate("techvault.wazuh-manager", "debian:12-slim")
        assert started == [("techvault.wazuh-manager", "debian:12-slim")]


class TestPackages:
    def test_install_runs_generic_manager_command_in_the_node_container(self):
        fake = _FakeExec()
        _executor(fake).install_packages("techvault.wazuh-manager", "apt", ("wazuh-manager",))
        container, argv = fake.calls[-1]
        assert container == "aptl-wazuh-manager"
        assert "apt-get" in argv and "install" in argv and "wazuh-manager" in argv

    def test_install_nonzero_raises_translatable_command_error(self):
        fake = _FakeExec(lambda c, a: (100, "E: Unable to locate package"))
        executor = _executor(fake)
        with pytest.raises(MaterializationCommandError):
            executor.install_packages("n.node", "apt", ("nope",))

    def test_apt_install_refreshes_index_before_installing(self):
        # A slim base image ships no apt lists, so install must be preceded by
        # `apt-get update`. Regression guard for a real failure fakes missed.
        fake = _FakeExec()
        _executor(fake).install_packages("n.node", "apt", ("curl",))
        argvs = fake.argvs()
        update_idx = next(i for i, a in enumerate(argvs) if "update" in a)
        install_idx = next(i for i, a in enumerate(argvs) if "install" in a)
        assert update_idx < install_idx

    def test_observe_installed_parses_manager_query_output(self):
        def responder(container, argv):
            if "dpkg-query" in argv:
                return 0, "curl\nwazuh-manager\n"
            return 0, ""

        observed = _executor(_FakeExec(responder)).observe_installed_packages(
            "n.node", "apt", ("curl", "wazuh-manager", "absent")
        )
        assert observed == frozenset({"curl", "wazuh-manager"})


class TestIdentity:
    def test_ensure_group_is_idempotent_groupadd(self):
        fake = _FakeExec()
        _executor(fake).ensure_group("n.node", "wazuh", 1000)
        argv = fake.calls[-1][1]
        assert argv[0] == "groupadd" and "-f" in argv and argv[-1] == "wazuh"
        assert "-g" in argv and "1000" in argv

    def test_ensure_user_skips_creation_when_user_exists(self):
        # id -u returns 0 -> user already present -> no useradd.
        fake = _FakeExec(lambda c, a: (0, "1000") if a[0] == "id" else (0, ""))
        _executor(fake).ensure_user("n.node", EnsureUserOp(username="wazuh"))
        assert not any(argv[0] == "useradd" for argv in fake.argvs())

    def test_ensure_user_creates_when_absent_with_declared_attrs(self):
        fake = _FakeExec(lambda c, a: (1, "") if a[0] == "id" else (0, ""))
        _executor(fake).ensure_user(
            "n.node",
            EnsureUserOp(username="wazuh", shell="/bin/bash", supplemental_groups=("wazuh",)),
        )
        useradd = next(argv for argv in fake.argvs() if argv[0] == "useradd")
        assert useradd[-1] == "wazuh"
        assert "/bin/bash" in useradd and "wazuh" in useradd  # shell + group

    def test_observe_local_user_and_group_from_returncode(self):
        present = _executor(_FakeExec(lambda c, a: (0, "")))
        absent = _executor(_FakeExec(lambda c, a: (1, "")))
        assert present.observe_local_user("n.node", "wazuh") is True
        assert absent.observe_local_user("n.node", "wazuh") is False
        assert present.observe_local_group("n.node", "wazuh") is True
        assert absent.observe_local_group("n.node", "wazuh") is False


class TestFilesystem:
    def test_ensure_directory_mkdirs_then_chowns_and_chmods(self):
        fake = _FakeExec()
        _executor(fake).ensure_directory(
            "n.node", EnsureDirectoryOp(path="/var/log/named", owner="bind", group="bind", mode="0755")
        )
        argvs = fake.argvs()
        assert ["mkdir", "-p", "/var/log/named"] in argvs
        assert ["chown", "bind:bind", "/var/log/named"] in argvs
        assert ["chmod", "0755", "/var/log/named"] in argvs

    def test_ensure_directory_skips_chown_and_chmod_when_undeclared(self):
        fake = _FakeExec()
        _executor(fake).ensure_directory("n.node", EnsureDirectoryOp(path="/srv/data"))
        argvs = fake.argvs()
        assert argvs == [["mkdir", "-p", "/srv/data"]]

    def test_ensure_directory_nonzero_raises_translatable_command_error(self):
        fake = _FakeExec(lambda c, a: (1, "mkdir: cannot create directory"))
        executor = _executor(fake)
        op = EnsureDirectoryOp(path="/root-owned")
        with pytest.raises(MaterializationCommandError):
            executor.ensure_directory("n.node", op)

    def test_observe_directory_from_returncode(self):
        present = _executor(_FakeExec(lambda c, a: (0, "")))
        absent = _executor(_FakeExec(lambda c, a: (1, "")))
        assert present.observe_directory("n.node", "/var/log/named") is True
        assert absent.observe_directory("n.node", "/var/log/named") is False


class TestServices:
    def test_enable_and_start_run_systemctl(self):
        fake = _FakeExec()
        ex = _executor(fake)
        ex.enable_service_unit("n.node", "wazuh-manager.service")
        ex.start_service_unit("n.node", "wazuh-manager.service")
        argvs = fake.argvs()
        assert ["systemctl", "enable", "wazuh-manager.service"] in argvs
        assert ["systemctl", "start", "wazuh-manager.service"] in argvs

    def test_observe_active_and_enabled_parse_systemctl(self):
        active = _executor(_FakeExec(lambda c, a: (0, "active\n")))
        inactive = _executor(_FakeExec(lambda c, a: (3, "inactive\n")))
        assert active.observe_service_unit_active("n.node", "u.service") is True
        assert inactive.observe_service_unit_active("n.node", "u.service") is False
        enabled = _executor(_FakeExec(lambda c, a: (0, "enabled\n")))
        assert enabled.observe_service_unit_enabled("n.node", "u.service") is True
