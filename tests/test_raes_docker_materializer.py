"""Tests for the concrete Docker materialization executor (ADR-048).

The executor implements the generic `MaterializationExecutor` surface by running
generic OS commands (package manager, `groupadd`/`useradd`/`getent`/`id`,
`systemctl`) inside a node's base-OS container via an injected exec callable. It
is product-agnostic: dispatch never depends on any node or product name. Tests
drive it with a fake exec that records commands and returns canned outcomes, so
no Docker daemon is needed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptl.backends.raes_docker_materializer import (
    DockerMaterializationExecutor,
    MaterializationCommandError,
)
from aptl.core.deployment.errors import BackendSeedError
from aptl.backends.raes_materializer import (
    EnsureDirectoryOp,
    EnsureUserOp,
    InstallDependencyManifestOp,
    InstallSoftwareComponentOp,
    PlacePackArtifactOp,
    ProvisionDomainAuthorityOp,
    SetFilesystemMetadataOp,
)


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


class _FakeInputExec:
    def __init__(self, responder=None) -> None:
        self.calls: list[tuple[str, list[str], str]] = []
        self._responder = responder or (lambda container, argv, payload: 0)

    def __call__(self, container: str, argv: list[str], payload: str):
        self.calls.append((container, argv, payload))
        return SimpleNamespace(
            returncode=self._responder(container, argv, payload), stdout=""
        )


def _executor(
    exec_fn, *, started=None, sleep=None, input_fn=None, offline_staged=False
):
    def start_base(addr, image):
        if started is not None:
            started.append((addr, image))

    return DockerMaterializationExecutor(
        run=exec_fn,
        run_with_input=input_fn,
        container_for=lambda addr: "aptl-" + addr.rsplit(".", 1)[-1],
        start_base=start_base,
        # Real time.sleep would make retry tests (and the unrelated failure
        # tests that now also exhaust the refresh retry) take ~15s each.
        sleep=sleep or (lambda seconds: None),
        offline_staged=offline_staged,
    )


class TestBaseSubstrate:
    def test_ensure_base_substrate_starts_the_base_container(self):
        started: list[tuple[str, str]] = []
        ex = _executor(_FakeExec(), started=started)
        ex.ensure_base_substrate("techvault.wazuh-manager", "debian:13-slim")
        assert started == [("techvault.wazuh-manager", "debian:13-slim")]


class TestPackages:
    def test_preinstalled_packages_need_no_index_or_install(self):
        def responder(container, argv):
            if "dpkg-query" in argv:
                return 0, "postgresql\n"
            raise AssertionError(f"unexpected package command: {argv}")

        fake = _FakeExec(responder)
        _executor(fake).install_packages("n.db", "apt", ("postgresql",))
        assert len(fake.calls) == 1

    def test_offline_missing_package_fails_without_attempting_download(self):
        fake = _FakeExec(lambda _container, _argv: (1, ""))
        with pytest.raises(
            MaterializationCommandError, match="offline image is missing"
        ):
            _executor(fake, offline_staged=True).install_packages(
                "n.db", "apt", ("postgresql",)
            )
        assert len(fake.calls) == 1

    def test_install_runs_generic_manager_command_in_the_node_container(self):
        fake = _FakeExec()
        _executor(fake).install_packages(
            "techvault.wazuh-manager", "apt", ("wazuh-manager",)
        )
        container, argv = fake.calls[-1]
        assert container == "aptl-wazuh-manager"
        assert "apt-get" in argv
        assert "install" in argv
        assert "wazuh-manager" in argv

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


class TestPackageIndexRefreshRetry:
    """A just-started container's network isn't always immediately ready:
    the first `apt-get update` after `docker run` can transiently fail
    (issue #581, root-caused via a real fresh-VM reproduction showing 4/5
    fresh containers fail immediately, 0/5 fail after a 1s delay). The
    refresh command is idempotent, so a bounded retry recovers from this
    without masking a genuine failure."""

    def test_transient_refresh_failure_recovers_then_installs(self):
        calls = {"update": 0}

        def responder(container, argv):
            if "update" in argv:
                calls["update"] += 1
                if calls["update"] < 3:
                    return 100, "W: GPG error"
                return 0, ""
            return 0, ""

        fake = _FakeExec(responder)
        sleeps: list[float] = []
        _executor(fake, sleep=sleeps.append).install_packages(
            "n.node", "apt", ("curl",)
        )

        assert calls["update"] == 3
        assert sleeps == [1.0, 2.0]
        assert any("install" in argv for argv in fake.argvs())

    def test_refresh_exhausts_all_retries_then_raises(self):
        fake = _FakeExec(
            lambda c, a: (100, "W: GPG error") if "update" in a else (0, "")
        )
        sleeps: list[float] = []
        executor = _executor(fake, sleep=sleeps.append)

        with pytest.raises(MaterializationCommandError):
            executor.install_packages("n.node", "apt", ("curl",))

        update_calls = sum(1 for argv in fake.argvs() if "update" in argv)
        assert update_calls == 5  # 1 initial attempt + 4 retries
        assert sleeps == [1.0, 2.0, 4.0, 8.0]
        assert not any("install" in argv for argv in fake.argvs())


class TestIdentity:
    def test_ensure_group_is_idempotent_groupadd(self):
        fake = _FakeExec()
        _executor(fake).ensure_group("n.node", "wazuh", 1000)
        argv = fake.calls[-1][1]
        assert argv[0] == "groupadd"
        assert "-f" in argv
        assert argv[-1] == "wazuh"
        assert "-g" in argv
        assert "1000" in argv

    def test_ensure_user_skips_creation_when_user_exists(self):
        # id -u returns 0 -> user already present -> no useradd.
        fake = _FakeExec(lambda c, a: (0, "1000") if a[0] == "id" else (0, ""))
        _executor(fake).ensure_user("n.node", EnsureUserOp(username="wazuh"))
        assert not any(argv[0] == "useradd" for argv in fake.argvs())

    def test_ensure_user_creates_when_absent_with_declared_attrs(self):
        fake = _FakeExec(lambda c, a: (1, "") if a[0] == "id" else (0, ""))
        _executor(fake).ensure_user(
            "n.node",
            EnsureUserOp(
                username="wazuh", shell="/bin/bash", supplemental_groups=("wazuh",)
            ),
        )
        useradd = next(argv for argv in fake.argvs() if argv[0] == "useradd")
        assert useradd[-1] == "wazuh"
        assert "/bin/bash" in useradd
        assert "wazuh" in useradd  # shell + group

    def test_ensure_user_rechecks_and_retries_a_transient_creation_failure(self):
        attempts = 0

        def responder(_container, argv):
            nonlocal attempts
            if argv[0] == "id":
                return (0, "1000") if attempts >= 2 else (1, "")
            if argv[0] == "useradd":
                attempts += 1
                return (1, "") if attempts == 1 else (0, "")
            return 0, ""

        sleeps = []
        fake = _FakeExec(responder)
        _executor(fake, sleep=sleeps.append).ensure_user(
            "n.node", EnsureUserOp(username="labadmin")
        )

        assert attempts == 2
        assert sleeps == [0.25]

    def test_observe_local_user_and_group_from_returncode(self):
        present = _executor(_FakeExec(lambda c, a: (0, "")))
        absent = _executor(_FakeExec(lambda c, a: (1, "")))
        assert present.observe_local_user("n.node", "wazuh") is True
        assert absent.observe_local_user("n.node", "wazuh") is False
        assert present.observe_local_group("n.node", "wazuh") is True
        assert absent.observe_local_group("n.node", "wazuh") is False


class TestFilesystem:
    def test_place_file_delivers_secret_only_on_stdin_and_reads_back_exact_bytes(self):
        secret = "lab flag with a quote ' and newline\n"
        fake_input = _FakeInputExec()
        digest = hashlib.sha256(secret.encode()).hexdigest()
        fake = _FakeExec(
            lambda _container, argv: (
                (0, f"{digest}  {argv[1]}") if argv[0] == "sha256sum" else (0, "")
            )
        )
        _executor(fake, input_fn=fake_input).place_file(
            "n.node", "/root/root.txt", secret, "0600"
        )

        assert len(fake_input.calls) == 1
        assert [call[1][0] for call in fake_input.calls] == ["sh"]
        assert all(call[2] == secret for call in fake_input.calls)
        assert all(secret not in " ".join(call[1]) for call in fake_input.calls)
        assert "base64" not in str(fake_input.calls)
        assert "chmod 0600" in fake_input.calls[0][1][2]
        assert fake.argvs() == [["sha256sum", "/root/root.txt"]]

    def test_place_file_accepts_exact_readback_after_lost_mutation_result(self):
        fake_input = _FakeInputExec(
            lambda _container, argv, _payload: 1 if argv[0] == "sh" else 0
        )
        digest = hashlib.sha256(b"value").hexdigest()
        fake = _FakeExec(lambda _container, argv: (0, f"{digest}  {argv[1]}"))
        sleeps = []

        _executor(fake, sleep=sleeps.append, input_fn=fake_input).place_file(
            "n.node", "/tmp/a", "value"
        )

        assert len(fake_input.calls) == 1
        assert sleeps == []

    def test_place_file_retries_when_readback_does_not_match(self):
        checks = 0
        digest = hashlib.sha256(b"value").hexdigest()

        def responder(_container, argv):
            nonlocal checks
            checks += 1
            value = "0" * 64 if checks == 1 else digest
            return 0, f"{value}  {argv[1]}"

        fake_input = _FakeInputExec()
        fake = _FakeExec(responder)
        sleeps = []
        _executor(fake, sleep=sleeps.append, input_fn=fake_input).place_file(
            "n.node", "/tmp/a", "value"
        )

        assert [call[1][0] for call in fake_input.calls] == ["sh", "sh"]
        assert fake.argvs() == [["sha256sum", "/tmp/a"]] * 2
        assert sleeps == [0.25]

    def test_place_file_fails_closed_when_exact_readback_never_matches(self):
        fake_input = _FakeInputExec(lambda _container, argv, _payload: 1)
        fake = _FakeExec(lambda _container, argv: (1, ""))
        sleeps = []
        executor = _executor(fake, sleep=sleeps.append, input_fn=fake_input)

        with pytest.raises(MaterializationCommandError):
            executor.place_file("n.node", "/tmp/a", "value")

        assert len(fake_input.calls) == 5
        assert fake.argvs() == [["sha256sum", "/tmp/a"]] * 5
        assert sleeps == [0.25, 0.5, 1.0, 2.0]

    def test_ensure_directory_mkdirs_then_chowns_and_chmods(self):
        fake = _FakeExec()
        _executor(fake).ensure_directory(
            "n.node",
            EnsureDirectoryOp(
                path="/var/log/named", owner="bind", group="bind", mode="0755"
            ),
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

    def test_set_metadata_uses_discrete_chown_and_chmod_argv(self):
        fake = _FakeExec()
        op = SetFilesystemMetadataOp(
            path="/root/root.txt", owner="root", group="root", mode="0o600"
        )

        _executor(fake).set_filesystem_metadata("n.node", op)

        assert fake.argvs() == [
            ["chown", "root:root", "/root/root.txt"],
            ["chmod", "0600", "/root/root.txt"],
        ]

    def test_observe_metadata_requires_every_selected_dimension(self):
        def responder(container, argv):
            if argv[0] == "stat":
                return 0, "root:root:0:0:600\n"
            return 1, ""

        op = SetFilesystemMetadataOp(
            path="/root/root.txt",
            owner="root",
            group="root",
            uid=0,
            gid=0,
            mode="0600",
        )

        assert _executor(_FakeExec(responder)).observe_filesystem_metadata("n.node", op)


class TestDependencyManifest:
    def test_install_runs_ecosystem_install_against_the_manifest_directory(self):
        fake = _FakeExec()
        _executor(fake).install_dependency_manifest(
            "n.node",
            InstallDependencyManifestOp(ecosystem="pip", path="/app/pyproject.toml"),
        )
        assert fake.calls[-1][1] == [
            "pip",
            "install",
            "--break-system-packages",
            "/app",
        ]

    def test_offline_install_uses_local_source_without_resolution(self):
        fake = _FakeExec()
        _executor(fake, offline_staged=True).install_dependency_manifest(
            "n.node",
            InstallDependencyManifestOp(ecosystem="pip", path="/app/pyproject.toml"),
        )
        argv = fake.calls[-1][1]
        assert argv == [
            "pip",
            "install",
            "--break-system-packages",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "/app",
        ]

    def test_install_nonzero_raises_translatable_command_error(self):
        fake = _FakeExec(lambda c, a: (1, "error"))
        executor = _executor(fake)
        op = InstallDependencyManifestOp(ecosystem="pip", path="/app/pyproject.toml")
        with pytest.raises(MaterializationCommandError):
            executor.install_dependency_manifest("n.node", op)

    def test_observe_installed_queries_by_declared_name(self):
        fake = _FakeExec(lambda c, a: (0, ""))
        observed = _executor(fake).observe_dependency_manifest_installed(
            "n.node",
            InstallDependencyManifestOp(
                ecosystem="pip", path="/app/pyproject.toml", name="aptl-labs"
            ),
        )
        assert observed is True
        assert fake.calls[-1][1] == ["pip", "show", "aptl-labs"]

    def test_observe_installed_false_when_query_fails(self):
        fake = _FakeExec(lambda c, a: (1, ""))
        observed = _executor(fake).observe_dependency_manifest_installed(
            "n.node",
            InstallDependencyManifestOp(
                ecosystem="pip", path="/app/pyproject.toml", name="aptl-labs"
            ),
        )
        assert observed is False


class TestSoftwareComponent:
    def test_npm_component_uses_exact_lockfile_then_builds(self):
        fake = _FakeExec()
        op = InstallSoftwareComponentOp(
            ecosystem="npm",
            manifest_path="/opt/mcp/common/package-lock.json",
            package_name="aptl-mcp-common",
            version="0.1.0",
        )

        _executor(fake).install_software_component("n.node", op)

        assert fake.argvs() == [
            ["npm", "--prefix", "/opt/mcp/common", "ci", "--include=dev"],
            ["npm", "--prefix", "/opt/mcp/common", "run", "build", "--if-present"],
        ]

    def test_offline_npm_component_uses_preloaded_cache_only(self):
        fake = _FakeExec()
        op = InstallSoftwareComponentOp(
            ecosystem="npm",
            manifest_path="/opt/mcp/common/package-lock.json",
            package_name="aptl-mcp-common",
            version="0.1.0",
        )

        _executor(fake, offline_staged=True).install_software_component("n.node", op)

        assert fake.argvs() == [
            ["npm", "--prefix", "/opt/mcp/common", "ci", "--include=dev", "--offline"],
            ["npm", "--prefix", "/opt/mcp/common", "run", "build", "--if-present"],
        ]

    def test_observation_requires_exact_identity_and_declared_output(self):
        package = (
            '{"name":"aptl-mcp-common","version":"0.1.0","main":"./build/index.js"}'
        )

        def responder(container, argv):
            if argv[:4] == ["npm", "--prefix", "/opt/mcp/common", "pkg"]:
                return 0, package
            if argv == ["test", "-f", "/opt/mcp/common/build/index.js"]:
                return 0, ""
            return 1, ""

        observed = _executor(_FakeExec(responder)).observe_software_component(
            "n.node",
            InstallSoftwareComponentOp(
                ecosystem="npm",
                manifest_path="/opt/mcp/common/package-lock.json",
                package_name="aptl-mcp-common",
                version="0.1.0",
            ),
        )

        assert observed is True

    def test_observation_rejects_unsafe_or_missing_outputs(self):
        package = '{"name":"aptl-mcp-common","version":"0.1.0","main":"../host-file"}'
        fake = _FakeExec(lambda container, argv: (0, package))

        observed = _executor(fake).observe_software_component(
            "n.node",
            InstallSoftwareComponentOp(
                ecosystem="npm",
                manifest_path="/opt/mcp/common/package-lock.json",
                package_name="aptl-mcp-common",
                version="0.1.0",
            ),
        )

        assert observed is False
        assert not any(argv[:2] == ["test", "-f"] for argv in fake.argvs())


class TestDomainAuthority:
    def test_provider_bootstrap_uses_discrete_authored_arguments(self):
        fake = _FakeExec()
        op = ProvisionDomainAuthorityOp(domain="EXAMPLE", realm="EXAMPLE.TEST")

        _executor(fake).provision_domain_authority("n.ad", op)

        assert [
            "aptl-provision-samba-domain",
            "EXAMPLE",
            "EXAMPLE.TEST",
        ] in fake.argvs()

    def test_observation_requires_exact_served_domain_identity(self):
        output = (
            "Forest : example.test\nDomain : example.test\nNetbios domain : EXAMPLE\n"
        )
        fake = _FakeExec(lambda container, argv: (0, output))

        observed = _executor(fake).observe_domain_authority(
            "n.ad",
            ProvisionDomainAuthorityOp(domain="EXAMPLE", realm="EXAMPLE.TEST"),
        )

        assert observed is True

    def test_observe_installed_fails_closed_without_a_declared_name(self):
        fake = _FakeExec(lambda c, a: (0, ""))
        observed = _executor(fake).observe_dependency_manifest_installed(
            "n.node",
            InstallDependencyManifestOp(ecosystem="pip", path="/app/pyproject.toml"),
        )
        assert observed is False


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


class _StubIdentity:
    def __init__(self, digest):
        self.digest = digest


class _StubResolved:
    """The shape ``resolve_pack_artifact`` returns: verified bytes + identity."""

    def __init__(self, data, digest):
        self.data = data
        self.identity = _StubIdentity(digest)


def _tar_bytes(members):
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


@pytest.fixture
def stub_pack(monkeypatch):
    """Replace the pack resolver with an in-memory ``artifact_id -> resolved`` map."""

    resolved = {}

    def _resolve(pack_root, artifact, **kwargs):
        return resolved[artifact]

    monkeypatch.setattr("raes_env_packs.resolve_pack_artifact", _resolve)
    return resolved


class TestPackArtifactPlacement:
    """Placing pack content into an image-free node (#875).

    The bytes are resolved by opaque id and byte-bound to the declared digest at
    execution time; no host path is read from the scenario. The executor stages
    the verified bytes and hands the staged path to the backend's copy-in.
    """

    def _executor_with_copy(self, tmp_path, copied, exec_fn=None):
        def _copy_in(container, src, dest, is_dir):
            # Record what the staged source actually holds: the executor is
            # responsible for the bytes it hands the backend's copy-in.
            staged = (
                sorted(child.name for child in Path(src).iterdir())
                if is_dir
                else Path(src).read_bytes()
            )
            copied.append((container, staged, dest, is_dir))

        return DockerMaterializationExecutor(
            run=exec_fn or _FakeExec(),
            container_for=lambda addr: "aptl-" + addr.rsplit(".", 1)[-1],
            start_base=lambda addr, image: None,
            copy_in=_copy_in,
            scenario_root=tmp_path,
        )

    def test_file_artifact_bytes_are_staged_and_copied_into_the_node(
        self, tmp_path, stub_pack
    ):
        digest = "sha256:" + "a" * 64
        stub_pack["flag-gen"] = _StubResolved(b"#!/bin/sh\n", digest)
        copied = []
        exec_fn = _FakeExec()
        ex = self._executor_with_copy(tmp_path, copied, exec_fn)

        ex.place_pack_artifact(
            "provision.node.webapp",
            PlacePackArtifactOp(
                dest_path="/opt/flags/generate.sh",
                artifact_id="flag-gen",
                artifact_digest=digest,
            ),
        )

        # The destination's parent is created inside the container first.
        assert exec_fn.argvs() == [["mkdir", "-p", "/opt/flags"]]
        assert copied == [
            ("aptl-webapp", b"#!/bin/sh\n", "/opt/flags/generate.sh", False)
        ]

    def test_directory_artifact_is_extracted_before_being_copied_in(
        self, tmp_path, stub_pack
    ):
        digest = "sha256:" + "b" * 64
        stub_pack["src"] = _StubResolved(
            _tar_bytes({"main.py": b"x\n", "README": b"y\n"}), digest
        )
        copied = []
        ex = self._executor_with_copy(tmp_path, copied)

        ex.place_pack_artifact(
            "provision.node.webapp",
            PlacePackArtifactOp(
                dest_path="/opt/app",
                artifact_id="src",
                artifact_digest=digest,
                is_directory=True,
            ),
        )

        container, members, dest, is_dir = copied[0]
        assert (container, dest, is_dir) == ("aptl-webapp", "/opt/app", True)
        assert members == ["README", "main.py"]

    def test_transient_pack_copy_failure_retries_exact_staged_bytes(
        self, tmp_path, stub_pack
    ):
        digest = "sha256:" + "b" * 64
        stub_pack["shares"] = _StubResolved(_tar_bytes({"Public/a": b"x"}), digest)
        attempts = []
        sleeps = []

        def copy(_container, src, _dest, _is_dir):
            attempts.append(Path(src, "Public", "a").read_bytes())
            if len(attempts) == 1:
                raise BackendSeedError("transient Docker copy failure")

        ex = DockerMaterializationExecutor(
            run=_FakeExec(),
            container_for=lambda _addr: "aptl-fileshare",
            start_base=lambda *_: None,
            copy_in=copy,
            scenario_root=tmp_path,
            sleep=sleeps.append,
        )

        ex.place_pack_artifact(
            "provision.node.fileshare",
            PlacePackArtifactOp(
                dest_path="/srv/shares",
                artifact_id="shares",
                artifact_digest=digest,
                is_directory=True,
            ),
        )

        assert attempts == [b"x", b"x"]
        assert sleeps == [0.25]

    def test_a_digest_mismatch_places_nothing(self, tmp_path, stub_pack):
        """Bytes that are not what the scenario pinned never reach the node."""

        stub_pack["flag-gen"] = _StubResolved(b"drifted\n", "sha256:" + "c" * 64)
        copied = []
        ex = self._executor_with_copy(tmp_path, copied)

        op = PlacePackArtifactOp(
            dest_path="/opt/flags/generate.sh",
            artifact_id="flag-gen",
            artifact_digest="sha256:" + "d" * 64,
        )

        with pytest.raises(MaterializationCommandError, match="digest mismatch"):
            ex.place_pack_artifact("provision.node.webapp", op)

        assert copied == []

    def test_placement_without_a_staged_pack_root_fails_closed(self):
        """No pack root means nothing can be resolved or verified."""

        ex = DockerMaterializationExecutor(
            run=_FakeExec(),
            container_for=lambda addr: "aptl-x",
            start_base=lambda addr, image: None,
        )

        op = PlacePackArtifactOp(
            dest_path="/opt/x", artifact_id="a", artifact_digest="sha256:0"
        )

        with pytest.raises(MaterializationCommandError, match="staged pack root"):
            ex.place_pack_artifact("provision.node.webapp", op)
