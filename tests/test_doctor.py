"""`aptl doctor` checks prerequisites without changing anything (#1218).

The checks are driven through the real `run_doctor` against a fake selected
daemon: a list-form runner answering the same read-only Docker queries a real
engine would. Host tools are resolved through an injected `which`, so each case
states exactly which prerequisite is missing.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import pytest

from aptl.core import hostenv
from aptl.core.deployment import get_backend as real_get_backend
from aptl.core.doctor import CheckStatus, run_doctor
from aptl.core.execution_boundary import ExecutionBoundaryObservation
from aptl.core.lifecycle_guard import canonical_lifecycle_project_root
from aptl.core.sysreqs import SysReqResult, ToolReqResult
from aptl.core.sysreqs import check_max_map_count as real_check_max_map_count

_ROOTFUL = '["name=seccomp,profile=builtin","name=cgroupns"]'
_ROOTLESS = '["name=seccomp,profile=builtin","name=rootless"]'
_USERNS = '["name=seccomp,profile=builtin","name=userns"]'
_PROBE_DETAIL = "/home/operator/.private/docker.sock endpoint-marker-7f3a"
# Loads as valid aptl.json; only the backend constructor refuses it.
_SSH_WITHOUT_HOST = json.dumps(
    {"lab": {"name": "doctor"}, "deployment": {"provider": "ssh-compose"}}
)
_READ_ONLY_QUERIES = {
    ("docker", "version"),
    ("docker", "info"),
    ("docker", "compose", "version"),
    ("docker", "context", "inspect"),
}
_CHECK_IDS = (
    "project-config",
    "workspace-writable",
    "docker-cli",
    "ssh-keygen",
    "node-npm",
    "docker-daemon",
    "docker-compose",
    "docker-buildx",
    "rootful-daemon",
    "systemd-substrate",
    "max-map-count",
    "docker-memory",
)
_DAEMON_CHECK_IDS = _CHECK_IDS[-4:]
# How the execution-boundary probe describes each kind of selected engine.
_BOUNDARIES = {
    "native-docker": ("local-unix", "native-linux", "observed"),
    "docker-vm-unverified": ("local-unix", "docker-vm", "observed"),
    "remote-unverified": ("remote-ssh", "unknown", "partial"),
    "unknown": ("unknown", "unknown", "unknown"),
}


class _FakeDaemon:
    """Answer doctor's read-only Docker queries like one selected engine."""

    def __init__(
        self,
        *,
        version="28.0.4",
        cgroup="2",
        security=_ROOTFUL,
        compose="2.29.1",
        memory=str(32 * 10**9),
        answers=True,
        stderr=f"Cannot connect to the Docker daemon at {_PROBE_DETAIL}",
    ):
        self.version = version
        self.cgroup = cgroup
        self.security = security
        self.compose = compose
        self.memory = memory
        self.answers = answers
        self.stderr = stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv, **_kwargs):
        self.calls.append(list(argv))
        if argv[:3] == ["docker", "compose", "version"]:
            return self._answer(argv, self.compose)
        if not self.answers:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr=self.stderr)
        return self._answer(argv, self._daemon_value(" ".join(argv)))

    def _daemon_value(self, joined):
        """Return the configured answer to one daemon query, if it is one."""
        answers = {
            "{{.Server.Version}}": self.version,
            "{{.CgroupVersion}}": self.cgroup,
            "{{json .SecurityOptions}}": self.security,
            "{{.MemTotal}}": self.memory,
        }
        return next(
            (value for query, value in answers.items() if query in joined), None
        )

    @staticmethod
    def _answer(argv, value):
        if value is None:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr=_PROBE_DETAIL)
        return subprocess.CompletedProcess(argv, 0, stdout=f"{value}\n", stderr="")


class _FakeBackend:
    def __init__(self, daemon: _FakeDaemon):
        self._run = daemon


def _project(tmp_path: Path, config: str | None = '{"lab": {"name": "doctor"}}'):
    project = tmp_path / "lab"
    project.mkdir()
    if config is not None:
        (project / "aptl.json").write_text(config, encoding="utf-8")
    return project


def _which(missing: tuple[str, ...] = ()):
    return lambda name: None if name in missing else f"/usr/bin/{name}"


def _boundary(containment):
    transport, runtime, status = _BOUNDARIES[containment]
    return ExecutionBoundaryObservation(
        transport=transport,
        override_source="none",
        daemon_runtime=runtime,
        host_containment=containment,
        observation_status=status,
        host_os="linux",
    )


@pytest.fixture
def host(mocker):
    """A host whose daemon, Buildx, sysctl and Node.js answer as configured.

    A native engine's ``vm.max_map_count`` reads ``state["max_map_count"]``,
    or the real check (with whatever sysctl a test stubs) when that is None.
    Every other engine goes through the real check, which reads nothing on
    this host for them.
    """

    state = {
        "daemon": _FakeDaemon(),
        "containment": "native-docker",
        "max_map_count": SysReqResult(
            passed=True, current_value=262144, required_value=262144
        ),
        "buildx": ToolReqResult(passed=True, command="docker buildx version"),
        "node": "v20.11.1\n",
    }

    def check_max_map_count(*, selected_mode):
        canned = state["max_map_count"]
        if selected_mode == hostenv.DOCKER_LINUX_NATIVE and canned is not None:
            return canned
        return real_check_max_map_count(selected_mode=selected_mode)

    state["get_backend"] = mocker.patch(
        "aptl.core.deployment.get_backend",
        side_effect=lambda *_args, **_kwargs: _FakeBackend(state["daemon"]),
    )
    mocker.patch(
        "aptl.core.execution_boundary.observe_execution_boundary",
        side_effect=lambda _backend: _boundary(state["containment"]),
    )
    state["check_max_map_count"] = mocker.patch(
        "aptl.core.sysreqs.check_max_map_count", side_effect=check_max_map_count
    )
    mocker.patch(
        "aptl.core.sysreqs.check_docker_buildx",
        side_effect=lambda: state["buildx"],
    )
    mocker.patch(
        "aptl.core.doctor._local_output",
        side_effect=lambda _argv: state["node"],
    )
    return state


def _by_id(report):
    return {check.check_id: check for check in report.checks}


def test_a_ready_host_passes_every_check(tmp_path, host):
    report = run_doctor(_project(tmp_path), which=_which())

    assert report.ok is True
    assert [check.check_id for check in report.checks] == list(_CHECK_IDS)
    assert {check.status for check in report.checks} == {CheckStatus.PASSED}
    assert all(check.fix == "" for check in report.checks)
    assert "Docker Engine 28.0.4" in _by_id(report)["docker-daemon"].summary


def test_doctor_changes_nothing_and_only_queries(tmp_path, host):
    """Read-only: the workspace is byte-identical and every probe is a query."""
    project = _project(tmp_path)
    (project / ".env").write_text("APTL_LAB_LABEL=unchanged\n", encoding="utf-8")

    def tree():
        return {
            path.relative_to(project): path.read_bytes()
            for path in sorted(project.rglob("*"))
            if path.is_file()
        }

    before = tree()

    run_doctor(project, which=_which())

    assert tree() == before
    assert sorted(path.name for path in project.iterdir()) == [".env", "aptl.json"]
    queries = {
        tuple(call[:3] if call[1] in {"compose", "context"} else call[:2])
        for call in host["daemon"].calls
    }
    assert queries <= _READ_ONLY_QUERIES


@pytest.mark.parametrize(
    ("change", "which_missing", "expected"),
    [
        pytest.param(
            {"config": None},
            (),
            ("project-config", CheckStatus.FAILED, "No aptl.json", "aptl lab init"),
            id="no-config",
        ),
        pytest.param(
            {"config": "{not json"},
            (),
            ("project-config", CheckStatus.FAILED, "not valid", "aptl config validate"),
            id="invalid-config",
        ),
        pytest.param(
            {},
            ("docker",),
            ("docker-cli", CheckStatus.FAILED, "not on PATH", "Docker Engine 28.0"),
            id="no-docker-cli",
        ),
        pytest.param(
            {},
            ("ssh-keygen",),
            ("ssh-keygen", CheckStatus.FAILED, "lab SSH keys", "OpenSSH"),
            id="no-ssh-keygen",
        ),
        pytest.param(
            {},
            ("npm",),
            ("node-npm", CheckStatus.WARNING, "degraded", "Node.js 20"),
            id="no-npm",
        ),
        pytest.param(
            {"node": "v18.19.0\n"},
            (),
            ("node-npm", CheckStatus.WARNING, "Node.js 20 or newer", "Node.js 20"),
            id="old-node",
        ),
        pytest.param(
            {"config": _SSH_WITHOUT_HOST, "real_backend": True},
            (),
            (
                "docker-daemon",
                CheckStatus.FAILED,
                "backend cannot be created",
                "needs ssh_host and ssh_user",
            ),
            id="unusable-backend",
        ),
        pytest.param(
            {"daemon": {"answers": False}},
            (),
            ("docker-daemon", CheckStatus.FAILED, "did not answer", "DOCKER_HOST"),
            id="daemon-down",
        ),
        pytest.param(
            {
                "daemon": {
                    "answers": False,
                    "stderr": "permission denied while trying to connect",
                }
            },
            (),
            (
                "docker-daemon",
                CheckStatus.FAILED,
                "cannot reach the Docker daemon socket",
                "host administrator",
            ),
            id="socket-permission",
        ),
        pytest.param(
            {"daemon": {"security": _ROOTLESS}},
            (),
            (
                "rootful-daemon",
                CheckStatus.FAILED,
                "rootless mode",
                "rootful Docker daemon",
            ),
            id="rootless",
        ),
        pytest.param(
            {"daemon": {"cgroup": "1"}},
            (),
            ("systemd-substrate", CheckStatus.FAILED, "cgroup v2", "cgroup v2 host"),
            id="cgroup-v1",
        ),
        pytest.param(
            {"daemon": {"version": "27.5.1"}},
            (),
            (
                "systemd-substrate",
                CheckStatus.FAILED,
                "reports 27.5",
                "Docker Engine 28.0",
            ),
            id="old-engine",
        ),
        pytest.param(
            {"daemon": {"version": "29.1.0", "security": _USERNS}},
            (),
            (
                "systemd-substrate",
                CheckStatus.FAILED,
                "userns-remap",
                "Turn off userns-remap in the Docker daemon configuration",
            ),
            id="userns-remap",
        ),
        pytest.param(
            {"daemon": {"compose": None}},
            (),
            (
                "docker-compose",
                CheckStatus.FAILED,
                "Compose v2 is not available",
                "Compose v2 plugin",
            ),
            id="no-compose",
        ),
        pytest.param(
            {
                "buildx": ToolReqResult(
                    passed=False,
                    command="docker buildx version",
                    error=_PROBE_DETAIL,
                    install_hint="Install the Docker Buildx plugin.",
                )
            },
            (),
            (
                "docker-buildx",
                CheckStatus.FAILED,
                "lab images need it",
                "Install the Docker Buildx plugin.",
            ),
            id="no-buildx",
        ),
        pytest.param(
            {
                "max_map_count": SysReqResult(
                    passed=False, current_value=65530, required_value=262144
                )
            },
            (),
            (
                "max-map-count",
                CheckStatus.FAILED,
                "vm.max_map_count is 65530; OpenSearch needs at least 262144",
                "sudo sysctl -w vm.max_map_count=262144",
            ),
            id="low-max-map-count",
        ),
        pytest.param(
            {"daemon": {"memory": str(8 * 10**9)}},
            (),
            ("docker-memory", CheckStatus.WARNING, "8.0 GB", "more memory"),
            id="low-memory",
        ),
    ],
)
def test_each_unmet_prerequisite_is_named_with_its_fix(
    tmp_path, host, change, which_missing, expected
):
    check_id, status, summary, fix = expected
    host["daemon"] = _FakeDaemon(**change.get("daemon", {}))
    if change.get("real_backend"):
        host["get_backend"].side_effect = real_get_backend
    for key in ("max_map_count", "buildx", "node"):
        if key in change:
            host[key] = change[key]
    project = _project(tmp_path, change.get("config", '{"lab": {"name": "doctor"}}'))

    report = run_doctor(project, which=_which(which_missing))

    check = _by_id(report)[check_id]
    assert check.status is status
    assert summary in check.summary
    assert fix in check.fix
    assert report.ok is (status is not CheckStatus.FAILED)


def _lab_start_compose_refusal(tmp_path, daemon, mocker):
    """Ask lab start's own Compose check about a scenario with Wazuh state."""
    from aptl.core.deployment.docker_compose import DockerComposeBackend

    mocker.patch(
        "aptl.core.deployment._compose_stateful_realization.owned_wazuh_services",
        return_value={"wazuh-manager"},
    )
    backend = DockerComposeBackend(tmp_path / "start", project_name="doctor")
    backend._run = daemon
    return backend._validate_stateful_compose_capability(None)


@pytest.mark.parametrize(
    ("answer", "status", "summary", "fix"),
    [
        pytest.param(
            "2.40.3+ds1-0ubuntu1~24.04.1",
            CheckStatus.PASSED,
            "Docker Compose 2.40 is available.",
            "",
            id="ubuntu-noble-package",
        ),
        pytest.param(
            "2.29.1-desktop.1",
            CheckStatus.PASSED,
            "Docker Compose 2.29 is available.",
            "",
            id="docker-desktop",
        ),
        pytest.param(
            "v2.24.4",
            CheckStatus.PASSED,
            "Docker Compose 2.24 is available.",
            "",
            id="wazuh-floor",
        ),
        pytest.param(
            "2.24.3",
            CheckStatus.WARNING,
            "Docker Compose 2.24.3 is older than 2.24.4, which lab start requires "
            "for techvault",
            "Upgrade the Docker Compose plugin to 2.24.4 or newer.",
            id="below-the-wazuh-floor",
        ),
        pytest.param(
            "1.29.2",
            CheckStatus.FAILED,
            "Docker Compose v2 is not available",
            "Install the Docker Compose v2 plugin.",
            id="compose-v1",
        ),
    ],
)
def test_compose_is_read_the_way_lab_start_reads_it(
    tmp_path, host, mocker, answer, status, summary, fix
):
    """A Compose that lab start accepts for techvault's Wazuh services passes.

    Doctor parses the answer with lab start's parser, so a distribution build
    string passes. Older v2 releases that lab start refuses only for such a
    scenario are a warning.
    """
    host["daemon"] = _FakeDaemon(compose=answer)

    report = run_doctor(_project(tmp_path), which=_which())

    check = _by_id(report)["docker-compose"]
    assert check.status is status
    assert summary in check.summary
    assert fix in check.fix
    assert bool(check.fix) is bool(fix)
    refusal = _lab_start_compose_refusal(tmp_path, host["daemon"], mocker)
    assert (refusal is None) is (status is CheckStatus.PASSED)


def _without_docker_cli(tmp_path, _host):
    return _project(tmp_path), _which(("docker",))


def _without_project_directory(tmp_path, _host):
    return tmp_path / "absent", _which()


def _with_an_unusable_backend(tmp_path, host):
    host["get_backend"].side_effect = real_get_backend
    return _project(tmp_path, _SSH_WITHOUT_HOST), _which()


def _with_a_silent_daemon(tmp_path, host):
    host["daemon"] = _FakeDaemon(answers=False)
    return _project(tmp_path), _which()


@pytest.mark.parametrize(
    ("arrange", "failed", "skipped", "cause"),
    [
        pytest.param(
            _without_docker_cli,
            ("docker-cli",),
            _CHECK_IDS[5:],
            "docker-cli",
            id="no-docker-cli",
        ),
        pytest.param(
            _without_project_directory,
            ("project-config",),
            (
                "workspace-writable",
                "docker-daemon",
                "docker-compose",
                *_DAEMON_CHECK_IDS,
            ),
            "project-config",
            id="no-project-directory",
        ),
        pytest.param(
            _with_an_unusable_backend,
            ("docker-daemon",),
            ("docker-compose", *_DAEMON_CHECK_IDS),
            "docker-daemon",
            id="backend-cannot-be-created",
        ),
        pytest.param(
            _with_a_silent_daemon,
            ("docker-daemon",),
            _DAEMON_CHECK_IDS,
            "docker-daemon",
            id="silent-daemon",
        ),
    ],
)
def test_every_path_reports_every_check_in_order(
    tmp_path, host, arrange, failed, skipped, cause
):
    """A check that cannot run is skipped and names the check that stopped it."""
    project_dir, which = arrange(tmp_path, host)

    report = run_doctor(project_dir, which=which)

    assert [check.check_id for check in report.checks] == list(_CHECK_IDS)

    def ids(status):
        return [check.check_id for check in report.checks if check.status is status]

    assert ids(CheckStatus.FAILED) == list(failed)
    assert ids(CheckStatus.SKIPPED) == list(skipped)
    assert ids(CheckStatus.WARNING) == []
    assert all(
        f"(see {cause})" in check.summary
        for check in report.checks
        if check.status is CheckStatus.SKIPPED
    )


def test_a_missing_project_directory_is_named_and_never_probed(tmp_path, host):
    report = run_doctor(tmp_path / "absent", which=_which())

    check = _by_id(report)["project-config"]
    assert check.summary == (
        "The project directory does not exist or is not a directory."
    )
    assert "--project-dir" in check.fix
    assert host["daemon"].calls == []
    host["get_backend"].assert_not_called()


def test_a_project_subdirectory_resolves_to_the_root_lab_start_uses(tmp_path, host):
    """Like lab start and stop, doctor finds aptl.json in a parent directory."""
    project = _project(
        tmp_path,
        '{"lab": {"name": "doctor"}, "deployment": {"project_name": "doctor-sub"}}',
    )
    notes = project / "notes"
    notes.mkdir()

    report = run_doctor(notes, which=_which())

    assert _by_id(report)["project-config"].status is CheckStatus.PASSED
    (config, root), _ = host["get_backend"].call_args
    assert root == canonical_lifecycle_project_root(notes) == project.resolve()
    assert config.deployment.project_name == "doctor-sub"


@pytest.mark.parametrize(
    ("containment", "mode", "status", "summary", "fix"),
    [
        pytest.param(
            "native-docker",
            hostenv.DOCKER_LINUX_NATIVE,
            CheckStatus.PASSED,
            "vm.max_map_count is 262144.",
            "",
            id="native-linux",
        ),
        pytest.param(
            "docker-vm-unverified",
            hostenv.DOCKER_VM,
            CheckStatus.SKIPPED,
            "manages vm.max_map_count itself",
            "",
            id="docker-vm",
        ),
        pytest.param(
            "remote-unverified",
            hostenv.DOCKER_UNKNOWN,
            CheckStatus.WARNING,
            "the selected Docker engine is remote",
            "On the host that runs the selected Docker engine, run "
            "`sudo sysctl -w vm.max_map_count=262144`",
            id="remote",
        ),
        pytest.param(
            "unknown",
            hostenv.DOCKER_UNKNOWN,
            CheckStatus.WARNING,
            "doctor could not tell which host runs the selected Docker engine",
            "On the host that runs the selected Docker engine, run "
            "`sudo sysctl -w vm.max_map_count=262144`",
            id="unknown",
        ),
    ],
)
def test_max_map_count_is_asked_of_the_host_that_runs_the_engine(
    tmp_path, host, containment, mode, status, summary, fix
):
    host["containment"] = containment

    check = _by_id(run_doctor(_project(tmp_path), which=_which()))["max-map-count"]

    host["check_max_map_count"].assert_called_once_with(selected_mode=mode)
    assert check.status is status
    assert summary in check.summary
    assert fix in check.fix
    assert bool(check.fix) is bool(fix)


def test_a_native_host_whose_sysctl_has_no_such_key_is_skipped(tmp_path, host, mocker):
    """Lab start passes this case, so doctor skips it and says what it saw."""
    host["max_map_count"] = None
    mocker.patch(
        "aptl.core.sysreqs._run_max_map_count_sysctl",
        return_value=subprocess.CompletedProcess(
            ["sysctl", "vm.max_map_count"],
            1,
            stdout="",
            stderr="sysctl: unknown oid 'vm.max_map_count'",
        ),
    )

    check = _by_id(run_doctor(_project(tmp_path), which=_which()))["max-map-count"]

    assert check.status is CheckStatus.SKIPPED
    assert check.summary == (
        "Not checked: sysctl could not read vm.max_map_count on this host."
    )


def _unanswered_probes(host, _mocker):
    host["daemon"] = _FakeDaemon(answers=False)
    host["buildx"] = ToolReqResult(
        passed=False, command="docker buildx version", error=_PROBE_DETAIL
    )


def _answers_that_carry_probe_detail(host, mocker):
    host["daemon"] = _FakeDaemon(cgroup=_PROBE_DETAIL)
    host["max_map_count"] = None
    mocker.patch(
        "aptl.core.sysreqs._run_max_map_count_sysctl",
        return_value=subprocess.CompletedProcess(
            ["sysctl", "vm.max_map_count"],
            1,
            stdout="",
            stderr=f"sysctl: permission denied {_PROBE_DETAIL}",
        ),
    )


@pytest.mark.parametrize(
    "arrange",
    [
        pytest.param(_unanswered_probes, id="unanswered"),
        pytest.param(_answers_that_carry_probe_detail, id="answered"),
    ],
)
def test_diagnostics_never_echo_probe_output(tmp_path, host, mocker, caplog, arrange):
    """Daemon and sysctl output can name sockets or hosts; doctor keeps none of it.

    Neither the report nor any log record the run emits carries it.
    """
    caplog.set_level(logging.DEBUG, logger="aptl")
    arrange(host, mocker)

    report = run_doctor(_project(tmp_path), which=_which())

    rendered = json.dumps([(check.summary, check.fix) for check in report.checks])
    assert "endpoint-marker-7f3a" not in rendered
    assert ".private" not in rendered
    assert str(tmp_path) not in rendered
    assert "endpoint-marker-7f3a" not in caplog.text
