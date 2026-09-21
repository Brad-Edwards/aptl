"""Short-lived helper containers must not outlive the call that started them.

APTL runs throwaway containers to probe content, seed volumes, apply boundary
policy and generate certificates. Each relied on ``docker run --rm`` alone, and
``--rm`` only removes a container that *started and exited*. When the CLI is
killed first — which is exactly what ``subprocess.run(timeout=...)`` does — the
container survives: ``Created`` if the kill landed before start, still running
if after. It carried no name and no label, so nothing could find it again. A
lab on a rootless daemon left one behind this way for days.

Removal had the matching gap: ``docker rm -f`` without ``-v`` leaves the
container's anonymous volumes behind, with no label and no receipt that any
later cleanup could match.
"""

from __future__ import annotations

import subprocess

import pytest

from aptl.core.ephemeral_containers import (
    DOCKER_DAEMON_ERROR,
    EPHEMERAL_ROLE_LABEL,
    EphemeralContainer,
    remove_container_command,
)


def _completed(returncode: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, "", "")


class _Recorder:
    """A runner that records every command and answers with a scripted result."""

    def __init__(self, *, result=None, raises: Exception | None = None):
        self.calls: list[tuple[list[str], dict]] = []
        self._result = result if result is not None else _completed(0)
        self._raises = raises

    def __call__(self, command: list[str], **kwargs):
        self.calls.append((list(command), kwargs))
        if command[:2] == ["docker", "rm"]:
            return _completed(0)
        if self._raises is not None:
            raise self._raises
        return self._result

    def removals(self) -> list[list[str]]:
        return [command for command, _ in self.calls if command[:2] == ["docker", "rm"]]


class TestRemoveContainerCommand:
    def test_removal_takes_the_containers_anonymous_volumes_with_it(self):
        """``-v`` is what removes anonymous volumes; without it they orphan."""

        assert remove_container_command("abc123") == [
            "docker",
            "rm",
            "-f",
            "-v",
            "abc123",
        ]

    def test_an_unforced_removal_still_refuses_a_running_container(self):
        """Dropping ``-f`` must not also drop ``-v``."""

        assert remove_container_command("abc123", force=False) == [
            "docker",
            "rm",
            "-v",
            "abc123",
        ]


class TestIdentity:
    def test_every_helper_gets_a_distinct_name(self):
        """Two concurrent helpers of one role must never collide on the daemon."""

        names = {EphemeralContainer.for_role("content-probe").name for _ in range(50)}

        assert len(names) == 50

    def test_the_name_says_what_the_helper_is(self):
        helper = EphemeralContainer.for_role("volume-seed")

        assert helper.name.startswith("aptl-volume-seed-")

    def test_run_options_name_label_and_auto_remove_the_container(self):
        helper = EphemeralContainer.for_role("boundary")

        options = helper.run_options()

        assert "--rm" in options
        assert options[options.index("--name") + 1] == helper.name
        assert f"{EPHEMERAL_ROLE_LABEL}=boundary" in options

    @pytest.mark.parametrize("role", ["", "Upper", "has space", "../x", "a" * 41])
    def test_a_role_that_is_not_a_safe_token_is_refused(self, role):
        """The role lands in a container name and a label; it must be inert."""

        with pytest.raises(ValueError):
            EphemeralContainer.for_role(role)


class TestRunGuaranteesRemoval:
    def test_a_completed_run_is_left_to_auto_remove(self):
        """A helper that ran and exited was already removed by ``--rm``."""

        helper = EphemeralContainer.for_role("content-probe")
        run = _Recorder(result=_completed(0))

        result = helper.run(run, ["docker", "run", *helper.run_options(), "img"], timeout=30)

        assert result.returncode == 0
        assert run.removals() == []

    def test_an_ordinary_non_zero_exit_is_not_treated_as_a_leak(self):
        """Probes encode their answer in the exit code; that is not a failure."""

        helper = EphemeralContainer.for_role("content-probe")
        run = _Recorder(result=_completed(11))

        result = helper.run(run, ["docker", "run", "img"], timeout=30)

        assert result.returncode == 11
        assert run.removals() == []

    def test_a_timed_out_run_removes_the_helper_by_name(self):
        """The CLI was killed; the daemon-side container may still exist."""

        helper = EphemeralContainer.for_role("boundary")
        run = _Recorder(raises=subprocess.TimeoutExpired(["docker"], 30))

        with pytest.raises(subprocess.TimeoutExpired):
            helper.run(run, ["docker", "run", "img"], timeout=30)

        assert run.removals() == [remove_container_command(helper.name)]

    def test_any_failure_to_complete_the_run_removes_the_helper(self):
        """A backend timeout type, an OSError: the container state is unknown."""

        helper = EphemeralContainer.for_role("boundary")
        run = _Recorder(raises=RuntimeError("backend timed out"))

        with pytest.raises(RuntimeError, match="backend timed out"):
            helper.run(run, ["docker", "run", "img"], timeout=30)

        assert run.removals() == [remove_container_command(helper.name)]

    def test_a_docker_daemon_error_removes_the_helper(self):
        """Exit 125 is Docker's own failure, which can follow a successful create."""

        helper = EphemeralContainer.for_role("volume-seed")
        run = _Recorder(result=_completed(DOCKER_DAEMON_ERROR))

        result = helper.run(run, ["docker", "run", "img"], timeout=30)

        assert result.returncode == DOCKER_DAEMON_ERROR
        assert run.removals() == [remove_container_command(helper.name)]

    def test_the_original_failure_survives_a_failed_removal(self):
        """Cleanup is best effort; it must never replace the error that matters."""

        helper = EphemeralContainer.for_role("boundary")

        def run(command, **kwargs):
            if command[:2] == ["docker", "rm"]:
                raise OSError("daemon gone")
            raise subprocess.TimeoutExpired(["docker"], 30)

        with pytest.raises(subprocess.TimeoutExpired):
            helper.run(run, ["docker", "run", "img"], timeout=30)

    def test_run_keyword_arguments_reach_the_run_but_not_the_removal(self):
        """A payload or cwd belongs to the helper invocation, not to ``docker rm``."""

        helper = EphemeralContainer.for_role("boundary")
        run = _Recorder(raises=subprocess.TimeoutExpired(["docker"], 30))

        with pytest.raises(subprocess.TimeoutExpired):
            helper.run(run, ["docker", "run", "img"], timeout=30, input="payload")

        run_call, removal_call = run.calls
        assert run_call[1] == {"timeout": 30, "input": "payload"}
        assert "input" not in removal_call[1]

    def test_an_explicit_discard_runner_is_used_for_removal(self):
        """A stdin runner must not pipe its payload into ``docker rm``."""

        helper = EphemeralContainer.for_role("boundary")
        run = _Recorder(raises=subprocess.TimeoutExpired(["docker"], 30))
        discard = _Recorder()

        with pytest.raises(subprocess.TimeoutExpired):
            helper.run(run, ["docker", "run", "img"], timeout=30, discard=discard)

        assert run.removals() == []
        assert discard.removals() == [remove_container_command(helper.name)]
