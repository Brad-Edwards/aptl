"""Docker Compose content-placement realization (issue #689)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from aptl.core.content_seed import build_content_volume_seeds
from aptl.core.deployment.realization import DeploymentContentRealization

# Reuses the Suricata seeder image: it is already pulled unconditionally by
# every lab start (Suricata is part of the default profile set), so content
# realization introduces no new image dependency (ADR-043 "already in the
# lab's supply chain"). The image only needs `/bin/sh`, `mkdir`, and `cp`,
# which this Alpine-based image provides.
CONTENT_SEEDER_IMAGE = "jasonish/suricata:7.0"

# Content read-back is a short metadata probe against a local/remote Docker
# daemon. Keep it independently bounded so an unhealthy daemon cannot stall the
# SEM-218 disclosure gate after provisioning side effects have completed.
_CONTENT_PROBE_TIMEOUT = 30

# The probe communicates only a filesystem-kind class through its return code.
# stdout/stderr are deliberately ignored so content and backend output cannot
# enter snapshots, diagnostics, or logs.
_CONTENT_FILE_EXIT = 10
_CONTENT_DIRECTORY_EXIT = 11
_CONTENT_MISSING_EXIT = 12


class ComposeRealizationContentMixin:
    """Realize typed scenario content placements through Docker Compose."""

    def realize_content(
        self,
        content: Sequence[DeploymentContentRealization],
        *,
        seeder_image: str,
        scenario_root: Path,
    ) -> None:
        """Materialize typed content placements via the ADR-043 seed seam.

        Content sources are scenario-declared inputs; they resolve against
        ``scenario_root`` (the bundle root), not the engine checkout (#874).
        """

        if not content:
            return
        seeds = build_content_volume_seeds(scenario_root, content)
        self.seed_named_volumes(seeds, seeder_image=seeder_image)

    def observe_content_type(
        self,
        content: DeploymentContentRealization,
    ) -> str | None:
        """Read back a content destination's realized filesystem kind.

        The named volume is first inspected so Docker cannot create an empty
        volume as a side effect of observation. The actual probe mounts that
        project-owned volume read-only and returns a fixed exit-code class; it
        never reads or returns the destination's bytes.
        """

        self._assert_safe_relpath(content.dest_relpath)
        volume = f"{self._project_name}_{content.volume_suffix}"
        volume_result = self._run(
            [
                "docker",
                "volume",
                "inspect",
                volume,
                "--format",
                "{{json .Labels}}",
            ],
            timeout=_CONTENT_PROBE_TIMEOUT,
        )
        if volume_result.returncode != 0 or not self._content_volume_owned_by_project(
            volume_result.stdout,
            content.volume_suffix,
        ):
            return None

        destination = f"/dest/{content.dest_relpath}"
        script = (
            f'if [ -f "$1" ]; then exit {_CONTENT_FILE_EXIT}; fi; '
            f'if [ -d "$1" ]; then exit {_CONTENT_DIRECTORY_EXIT}; fi; '
            f"exit {_CONTENT_MISSING_EXIT}"
        )
        result = self._run(
            [
                "docker",
                "run",
                *(["--pull=never"] if self._offline_staged else []),
                "--rm",
                "--user",
                "0:0",
                "--network",
                "none",
                "--entrypoint",
                "/bin/sh",
                "-v",
                f"{volume}:/dest:ro",
                CONTENT_SEEDER_IMAGE,
                "-c",
                script,
                "aptl-content-probe",
                destination,
            ],
            timeout=_CONTENT_PROBE_TIMEOUT,
        )
        return {
            _CONTENT_FILE_EXIT: "file",
            _CONTENT_DIRECTORY_EXIT: "directory",
        }.get(result.returncode)

    def observe_bind_source_type(self, source: str) -> str | None:
        """Classify a realized bind-mount source's kind on the Docker host.

        Content delivered to an image node is a read-only bind, so the kind the
        container sees at the destination is the kind of this source. The probe
        is the same one :meth:`observe_content_type` uses -- a throwaway,
        network-less container that mounts the path read-only and communicates
        only an exit-code class -- so no binary from the observed container's
        image runs and no bytes are read. That matters for a distroless image
        (which has no ``test``) and for a run-to-completion node that has already
        exited (which cannot be exec'd into at all).

        ``--mount`` is used rather than ``-v`` deliberately: ``-v`` *creates* a
        missing source as an empty directory, which would fabricate a
        ``directory`` observation for a path that was never realized. ``--mount``
        fails instead, and a failed probe observes nothing.
        """

        if not source.startswith("/"):
            return None
        # When bind sources are visible to the daemon they are on this same host
        # (``supports_local_artifacts``), and APTL wrote them, so the kind is a
        # direct host stat: no throwaway container per bind, and no dependency on
        # a heavy image starting under the load of a just-booted range (which
        # timed out the probe). A missing path returns None -- the stat never
        # creates it -- so an unrealized bind still discloses nothing.
        if getattr(self, "supports_local_artifacts", False):
            host_path = Path(source)
            if host_path.is_file():
                return "file"
            if host_path.is_dir():
                return "directory"
            return None
        script = (
            f'if [ -f "$1" ]; then exit {_CONTENT_FILE_EXIT}; fi; '
            f'if [ -d "$1" ]; then exit {_CONTENT_DIRECTORY_EXIT}; fi; '
            f"exit {_CONTENT_MISSING_EXIT}"
        )
        result = self._run(
            [
                "docker",
                "run",
                *(["--pull=never"] if self._offline_staged else []),
                "--rm",
                "--user",
                "0:0",
                "--network",
                "none",
                "--entrypoint",
                "/bin/sh",
                "--mount",
                f"type=bind,src={source},dst=/probe,readonly",
                CONTENT_SEEDER_IMAGE,
                "-c",
                script,
                "aptl-bind-source-probe",
                "/probe",
            ],
            timeout=_CONTENT_PROBE_TIMEOUT,
        )
        return {
            _CONTENT_FILE_EXIT: "file",
            _CONTENT_DIRECTORY_EXIT: "directory",
        }.get(result.returncode)

    def _content_volume_owned_by_project(
        self,
        raw_labels: str,
        logical_volume: str,
    ) -> bool:
        """Return whether volume labels bind it to this Compose project."""

        try:
            labels = json.loads(raw_labels)
        except (json.JSONDecodeError, TypeError):
            return False
        return (
            isinstance(labels, dict)
            and labels.get("com.docker.compose.project") == self._project_name
            and labels.get("com.docker.compose.volume") == logical_volume
        )
