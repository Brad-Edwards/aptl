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

#: ``docker run`` exits 125 when the failure is Docker's own. That can follow a
#: successful create, leaving a container ``--rm`` will never see exit. Any
#: other code came from a container that ran, which ``--rm`` has removed.
DOCKER_DAEMON_ERROR = 125

_ROLE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
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


@dataclass(frozen=True)
class EphemeralContainer:
    """One named helper container that must not outlive the run starting it."""

    role: str
    name: str

    @classmethod
    def for_role(cls, role: str) -> EphemeralContainer:
        """Mint a daemon-unique identity for one helper invocation.

        The role becomes part of a container name and a label value, so it is
        restricted to a lowercase hyphenated token rather than escaped.
        """

        if len(role) > _ROLE_MAX_LENGTH or not _ROLE.fullmatch(role):
            raise ValueError(f"invalid ephemeral container role: {role!r}")
        return cls(role=role, name=f"aptl-{role}-{secrets.token_hex(6)}")

    def run_options(self) -> list[str]:
        """Return the ``docker run`` options that name, label and auto-remove it."""

        return [
            "--rm",
            "--name",
            self.name,
            "--label",
            f"{EPHEMERAL_ROLE_LABEL}={self.role}",
        ]

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

        try:
            run(remove_container_command(self.name), timeout=_DISCARD_TIMEOUT)
        except Exception:  # noqa: BLE001 - best effort; the caller's error is what reports
            log.warning("Could not remove ephemeral %s container %s", self.role, self.name)
