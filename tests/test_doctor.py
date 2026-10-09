"""`aptl doctor` checks prerequisites without changing anything (#1218).

The checks are driven through the real `run_doctor` against a fake selected
daemon: a list-form runner answering the same read-only Docker queries a real
engine would. Host tools are resolved through an injected `which`, so each case
states exactly which prerequisite is missing.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aptl.core.doctor import CheckStatus, run_doctor
from aptl.core.execution_boundary import ExecutionBoundaryObservation
from aptl.core.sysreqs import SysReqResult, ToolReqResult

_ROOTFUL = '["name=seccomp,profile=builtin","name=cgroupns"]'
_ROOTLESS = '["name=seccomp,profile=builtin","name=rootless"]'
_PROBE_DETAIL = "/home/operator/.private/docker.sock endpoint-marker-7f3a"
_READ_ONLY_QUERIES = {
    ("docker", "version"),
    ("docker", "info"),
    ("docker", "compose", "version"),
    ("docker", "context", "inspect"),
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


@pytest.fixture
def host(mocker):
    """A host whose daemon, Buildx, sysctl and Node.js answer as configured."""

    state = {
        "daemon": _FakeDaemon(),
        "containment": "native-docker",
        "max_map_count": SysReqResult(
            passed=True, current_value=262144, required_value=262144
        ),
        "buildx": ToolReqResult(passed=True, command="docker buildx version"),
        "node": "v20.11.1\n",
    }
    mocker.patch(
        "aptl.core.deployment.get_backend",
        side_effect=lambda *_args, **_kwargs: _FakeBackend(state["daemon"]),
    )
    mocker.patch(
        "aptl.core.execution_boundary.observe_execution_boundary",
        side_effect=lambda _backend: ExecutionBoundaryObservation(
            transport="local-unix",
            override_source="none",
            daemon_runtime="native-linux",
            host_containment=state["containment"],
            observation_status="observed",
            host_os="linux",
        ),
    )
    mocker.patch(
        "aptl.core.sysreqs.check_max_map_count",
        side_effect=lambda **_kwargs: state["max_map_count"],
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
    assert [check.check_id for check in report.checks] == [
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
    ]
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


def test_a_silent_daemon_skips_only_the_checks_that_need_it(tmp_path, host):
    host["daemon"] = _FakeDaemon(answers=False)

    report = run_doctor(_project(tmp_path), which=_which())

    statuses = {check.check_id: check.status for check in report.checks}
    assert statuses["docker-compose"] is CheckStatus.PASSED
    assert statuses["docker-buildx"] is CheckStatus.PASSED
    assert [
        check_id
        for check_id, status in statuses.items()
        if status is CheckStatus.SKIPPED
    ] == ["rootful-daemon", "systemd-substrate", "max-map-count", "docker-memory"]


def test_a_vm_engine_does_not_ask_this_host_for_max_map_count(tmp_path, host):
    host["containment"] = "docker-vm-unverified"
    host["max_map_count"] = SysReqResult(
        passed=True, current_value=0, required_value=262144, applicable=False
    )

    check = _by_id(run_doctor(_project(tmp_path), which=_which()))["max-map-count"]

    assert check.status is CheckStatus.SKIPPED
    assert "manages vm.max_map_count itself" in check.summary


def test_diagnostics_never_echo_probe_output(tmp_path, host):
    """Daemon errors can name sockets or hosts; doctor keeps none of that."""
    host["daemon"] = _FakeDaemon(answers=False)
    host["buildx"] = ToolReqResult(
        passed=False, command="docker buildx version", error=_PROBE_DETAIL
    )

    report = run_doctor(_project(tmp_path), which=_which())

    rendered = json.dumps([(check.summary, check.fix) for check in report.checks])
    assert "endpoint-marker-7f3a" not in rendered
    assert ".private" not in rendered
    assert str(tmp_path) not in rendered
