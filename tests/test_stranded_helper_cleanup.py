"""Teardown removes the helpers a killed ``aptl`` process strands.

In-process cleanup cannot run when the process itself dies. A helper that had
already started finishes its short job and ``--rm`` removes it, so the only
state that persists is a helper killed between create and start: inert,
``Created`` forever, and invisible to project-scoped teardown. A rootless lab
kept one for days. Each helper now carries its lab's project, and teardown
removes that project's helpers that are not running.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from aptl.core.deployment._compose_resource_ownership import WorkspaceOwnership
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.ephemeral_containers import (
    EPHEMERAL_PROJECT_LABEL,
    remove_container_command,
)


class _Daemon:
    """A scripted daemon: which helpers are stranded, and which calls fail."""

    def __init__(self, *, stranded=(), list_fails=False, remove_fails=()):
        self.stranded = list(stranded)
        self.list_fails = list_fails
        self.remove_fails = set(remove_fails)
        self.commands: list[list[str]] = []

    def __call__(self, cmd, *, timeout=None):
        self.commands.append(list(cmd))
        if cmd[:3] == ["docker", "ps", "-aq"]:
            if self.list_fails:
                return subprocess.CompletedProcess(cmd, 1, "", "daemon unavailable")
            return subprocess.CompletedProcess(
                cmd, 0, "".join(f"{native_id}\n" for native_id in self.stranded)
            )
        if cmd[:2] == ["docker", "rm"]:
            return subprocess.CompletedProcess(cmd, 1 if cmd[-1] in self.remove_fails else 0)
        return subprocess.CompletedProcess(cmd, 0, "")


def _backend(tmp_path: Path, daemon: _Daemon, *, with_ownership: bool = True):
    if with_ownership:
        WorkspaceOwnership.ensure(tmp_path, "lab")
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="lab")
    backend._run = daemon
    return backend


class TestRemoveStrandedHelpers:
    def test_this_projects_stranded_helpers_are_removed_with_their_volumes(
        self, tmp_path
    ):
        daemon = _Daemon(stranded=["aaa111", "bbb222"])
        backend = _backend(tmp_path, daemon)
        project = WorkspaceOwnership.load(tmp_path, "lab").project_name

        assert backend.remove_stranded_helpers() == []

        query = daemon.commands[0]
        assert f"label={EPHEMERAL_PROJECT_LABEL}={project}" in query
        assert "status=running" not in query
        removals = [c for c in daemon.commands if c[:2] == ["docker", "rm"]]
        assert removals == [
            remove_container_command("aaa111"),
            remove_container_command("bbb222"),
        ]

    def test_the_sweep_is_scoped_to_the_workspace_project_not_the_logical_name(
        self, tmp_path
    ):
        """``lab`` is shared by every workspace; the workspace project is not."""

        daemon = _Daemon()
        backend = _backend(tmp_path, daemon)

        backend.remove_stranded_helpers()

        assert f"label={EPHEMERAL_PROJECT_LABEL}=lab" not in daemon.commands[0]

    def test_a_workspace_that_never_started_has_nothing_to_sweep(self, tmp_path):
        """No ownership means no scoped helper could exist; and none is created."""

        daemon = _Daemon()
        backend = _backend(tmp_path, daemon, with_ownership=False)

        assert backend.remove_stranded_helpers() == []
        assert daemon.commands == []
        assert WorkspaceOwnership.load(tmp_path, "lab") is None

    def test_a_query_that_fails_is_reported_not_passed_over(self, tmp_path):
        backend = _backend(tmp_path, _Daemon(list_fails=True))

        assert backend.remove_stranded_helpers() == [
            "failed to list stranded helper containers"
        ]

    def test_a_removal_that_fails_is_reported(self, tmp_path):
        backend = _backend(tmp_path, _Daemon(stranded=["aaa111"], remove_fails={"aaa111"}))

        assert backend.remove_stranded_helpers() == [
            "failed to remove a stranded helper container"
        ]


class TestHelperScope:
    def test_a_helper_run_by_an_owned_workspace_is_scoped_to_it(self, tmp_path):
        backend = _backend(tmp_path, _Daemon())
        project = WorkspaceOwnership.load(tmp_path, "lab").project_name

        helper = backend._ephemeral_container("content-probe")

        assert helper.project == project
        assert f"{EPHEMERAL_PROJECT_LABEL}={project}" in helper.run_options()

    def test_scoping_a_helper_never_creates_workspace_state(self, tmp_path):
        """Resolving the scope must not publish ownership or change the attempt."""

        backend = _backend(tmp_path, _Daemon(), with_ownership=False)

        helper = backend._ephemeral_container("content-probe")

        assert helper.project is None
        assert WorkspaceOwnership.load(tmp_path, "lab") is None
        assert backend._resource_attempt_id is None


class _RecordingBackend:
    """Records the order in which teardown calls each cleanup step."""

    def __init__(self, tmp_path: Path) -> None:
        self.project_dir = tmp_path
        self.project_name = "test"
        self.events: list[str] = []

    def _build_command(self, action, profiles, *, compose_files=None):
        del profiles, compose_files
        return ["docker", "compose", action]

    def _run(self, cmd, *, timeout=None):
        del timeout
        self.events.append(cmd[-1])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def remove_generic_materializer_containers(self):
        self.events.append("generic")
        return []

    def remove_stranded_helpers(self):
        self.events.append("helpers")
        return []

    def remove_project_containers(self):
        self.events.append("containers")
        return []

    def remove_project_networks(self):
        self.events.append("networks")
        return []

    def observe_project_runtime(self):
        from aptl.core.deployment.backend_host_inventory import ProjectRuntimePresence

        self.events.append("verify")
        return ProjectRuntimePresence()


def test_stop_sweeps_after_resolving_the_project_and_before_networks(tmp_path):
    """Direct containers resolve the workspace project; networks must wait for
    the sweep, since a stranded helper could still reference one."""

    from aptl.core.deployment._compose_stop import stop_compose_lab

    backend = _RecordingBackend(tmp_path)

    assert stop_compose_lab(backend, [], remove_volumes=False, timeout=30).success

    events = backend.events
    assert events.index("generic") < events.index("helpers") < events.index("networks")


def test_a_failed_sweep_fails_stop_rather_than_passing(tmp_path):
    from aptl.core.deployment._compose_stop import stop_compose_lab

    backend = _RecordingBackend(tmp_path)
    backend.remove_stranded_helpers = lambda: [
        "failed to remove a stranded helper container"
    ]

    result = stop_compose_lab(backend, [], remove_volumes=False, timeout=30)

    assert result.success is False
    assert "stranded helper" in result.error


def test_kill_sweeps_stranded_helpers(tmp_path):
    from aptl.core.deployment._compose_lifecycle import kill_compose_lab

    backend = _RecordingBackend(tmp_path)

    kill_compose_lab(backend, [], timeout=30)

    assert "helpers" in backend.events
    assert backend.events.index("generic") < backend.events.index("helpers")


def test_an_unreachable_daemon_is_a_reported_failure_not_an_exception(tmp_path):
    """Teardown continues and reports; the sweep never aborts the other steps."""

    from aptl.core.deployment.errors import BackendTimeoutError

    WorkspaceOwnership.ensure(tmp_path, "lab")
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="lab")

    def unreachable(cmd, *, timeout=None):
        raise BackendTimeoutError("docker ps timed out after 60s")

    backend._run = unreachable

    assert backend.remove_stranded_helpers() == [
        "failed to list stranded helper containers"
    ]


def test_an_unreadable_ownership_state_is_a_reported_failure_not_an_exception(
    tmp_path,
):
    """A conflicted workspace must not abort the teardown steps after the sweep."""

    from aptl.core.deployment._compose_resource_ownership import OwnershipConflictError

    backend = DockerComposeBackend(project_dir=tmp_path, project_name="lab")

    def conflicted():
        raise OwnershipConflictError("workspace ownership state is unavailable")

    backend._load_resource_ownership = conflicted
    backend._run = _Daemon(stranded=["aaa111"])

    assert backend.remove_stranded_helpers() == [
        "failed to list stranded helper containers"
    ]


def test_one_removal_timing_out_does_not_skip_the_rest(tmp_path):
    """Every stranded helper gets its removal attempt; each failure is reported."""

    from aptl.core.deployment.errors import BackendTimeoutError

    WorkspaceOwnership.ensure(tmp_path, "lab")
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="lab")
    daemon = _Daemon(stranded=["slow111", "fast222"])

    def run(cmd, *, timeout=None):
        if cmd[:2] == ["docker", "rm"] and cmd[-1] == "slow111":
            daemon.commands.append(list(cmd))
            raise BackendTimeoutError("docker rm timed out after 60s")
        return daemon(cmd, timeout=timeout)

    backend._run = run

    assert backend.remove_stranded_helpers() == [
        "failed to remove a stranded helper container"
    ]
    assert remove_container_command("fast222") in daemon.commands


def test_a_helper_minted_under_a_conflicted_workspace_still_runs_unscoped(tmp_path):
    """Scoping is best effort at mint time; the operations that need authority
    are the ones that report a conflicted workspace."""

    from aptl.core.deployment._compose_resource_ownership import OwnershipConflictError

    backend = DockerComposeBackend(project_dir=tmp_path, project_name="lab")

    def conflicted():
        raise OwnershipConflictError("workspace ownership state is unavailable")

    backend._load_resource_ownership = conflicted

    assert backend._ephemeral_container("content-probe").project is None
