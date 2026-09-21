"""Identity and guaranteed removal for APTL's short-lived helper containers.

APTL runs throwaway containers to probe content, seed volumes, apply boundary
policy, mirror traffic and generate certificates. ``docker run --rm`` alone does
not make them throwaway. ``--rm`` removes a container only when it *started and
exited*; when the CLI is killed first, the daemon-side container survives —
``Created`` if the kill landed before start, running if after — and
``subprocess.run(timeout=...)`` kills the CLI on exactly the timeout paths every
helper here sets. Such a container carried no name and no label, so nothing
could find it again: a lab on a rootless daemon left one behind for days.

:class:`EphemeralContainer` closes that gap without widening anyone's authority.
It names the helper so the run that created it can remove exactly that
container when the run does not complete — the same container ``--rm`` would
have removed, identified by a name this process chose a moment earlier.

:func:`remove_container_command` closes the matching removal gap: ``docker rm``
without ``-v`` leaves a container's anonymous volumes behind with no label and
no receipt, unreachable by any later cleanup. ``-v`` removes anonymous volumes
only; a named volume is never touched by it.

A helper can still be stranded when the ``aptl`` process itself is killed,
because then no Python cleanup runs. Only one state persists: a helper that had
already started finishes its short job and ``--rm`` removes it, so what remains
is a helper killed between create and start, inert and ``Created`` forever.
Each helper therefore carries its lab's project, and teardown removes that
project's helpers that are not running (:func:`stranded_helpers_command`). The
project label is deliberately not ``aptl.lifecycle.project``: presence checks
read that one, and a stranded husk is debris to remove, not a running lab.

Standard library only, so the lightweight pre-commit hook environment that
imports :mod:`aptl.core.suricata_seed` can import this too.
"""

from __future__ import annotations

import re
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from aptl.utils.logging import get_logger

log = get_logger("core.ephemeral_containers")

#: Label carried by every helper, naming what it is for.
EPHEMERAL_ROLE_LABEL = "aptl.ephemeral.role"

#: Label naming the lab project a helper acts for, so its teardown can find it.
EPHEMERAL_PROJECT_LABEL = "aptl.ephemeral.project"

#: ``docker run`` exits 125 when the failure is Docker's own. That can follow a
#: successful create, leaving a container ``--rm`` will never see exit. Any
#: other code came from a container that ran, which ``--rm`` has removed.
DOCKER_DAEMON_ERROR = 125

_ROLE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
#: Compose's own project-name grammar, so the label value is a name Docker
#: could have assigned a project and nothing more.
_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
#: Every state in which a helper is not doing work. A running helper may belong
#: to an operation still in flight, so it is never removed from outside.
_STRANDED_STATES = ("created", "exited", "dead")
_ROLE_MAX_LENGTH = 40
_DISCARD_TIMEOUT = 30

Runner = Callable[..., subprocess.CompletedProcess]


def remove_container_command(reference: str, *, force: bool = True) -> list[str]:
    """Return the argv that removes one container and its anonymous volumes.

    ``force=False`` keeps ``docker rm``'s refusal to remove a running container,
    for a caller whose contract is to remove only a container that has already
    completed; ``-v`` applies either way.
    """

    return ["docker", "rm", *(["-f"] if force else []), "-v", reference]


def stranded_helpers_command(project: str) -> list[str]:
    """Return the query for one project's helpers that are not running.

    Scoped by both the project label and the role label, so a node container —
    which never carries a role — cannot match, and another lab's helpers carry
    a different project.
    """

    return [
        "docker",
        "ps",
        "-aq",
        "--filter",
        f"label={EPHEMERAL_PROJECT_LABEL}={project}",
        "--filter",
        f"label={EPHEMERAL_ROLE_LABEL}",
        *(item for state in _STRANDED_STATES for item in ("--filter", f"status={state}")),
    ]


@dataclass(frozen=True)
class EphemeralContainer:
    """One named helper container that must not outlive the run starting it."""

    role: str
    name: str
    project: str | None = None

    @classmethod
    def for_role(cls, role: str, *, project: str | None = None) -> EphemeralContainer:
        """Mint a daemon-unique identity for one helper invocation.

        The role becomes part of a container name and a label value, so it is
        restricted to a lowercase hyphenated token rather than escaped.
        ``project`` scopes the helper to its lab so that lab's teardown can
        remove it if it is stranded; without it the helper is still removed
        in-process, but nothing claims it afterwards.
        """

        if len(role) > _ROLE_MAX_LENGTH or not _ROLE.fullmatch(role):
            raise ValueError(f"invalid ephemeral container role: {role!r}")
        if project is not None and not _PROJECT.fullmatch(project):
            raise ValueError(f"invalid ephemeral container project: {project!r}")
        return cls(role=role, name=f"aptl-{role}-{secrets.token_hex(6)}", project=project)

    def run_options(self) -> list[str]:
        """Return the ``docker run`` options that name, label and auto-remove it."""

        options = [
            "--rm",
            "--name",
            self.name,
            "--label",
            f"{EPHEMERAL_ROLE_LABEL}={self.role}",
        ]
        if self.project is not None:
            options += ["--label", f"{EPHEMERAL_PROJECT_LABEL}={self.project}"]
        return options

    def run(
        self,
        run: Runner,
        command: list[str],
        *,
        timeout: int,
        discard: Runner | None = None,
        **run_kwargs: object,
    ) -> subprocess.CompletedProcess:
        """Run the helper, removing it by name if the run does not complete.

        ``discard`` removes the helper when given; otherwise ``run`` does. Pass
        it for a runner that feeds stdin, so the payload never reaches
        ``docker rm``. The run's own exception or result is returned or
        re-raised unchanged: removal is best effort and never replaces it.
        """

        try:
            result = run(command, timeout=timeout, **run_kwargs)
        except Exception:
            self.discard(discard or run)
            raise
        if result.returncode == DOCKER_DAEMON_ERROR:
            self.discard(discard or run)
        return result

    def discard(self, run: Runner) -> None:
        """Remove this helper and its anonymous volumes, tolerating absence."""

        # Best effort by design: any failure here is logged and swallowed so it
        # can never replace the run's own error, which is the one that reports.
        try:
            run(remove_container_command(self.name), timeout=_DISCARD_TIMEOUT)
        except Exception:
            log.warning("Could not remove ephemeral %s container %s", self.role, self.name)
