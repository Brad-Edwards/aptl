"""``_NoStartBackend``: the offline deployment-backend stub for the RAES static
validation gate (SCN-010E / #322).

Split out of ``_gate_checks.py`` (module-length budget). The static gate
compiles, plans, and interprets a scenario but must never bring up Docker; this
stub simulates realization and reports back exactly the topology it was asked
to realize, so the offline conformance run observes a faithful realization of
the scenario under test without starting any container.
"""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from aptl.core.deployment._compose_realization_networks import _concrete_network_name
from aptl.core.lab_types import LabResult, LabStatus

if TYPE_CHECKING:
    from aptl.core.deployment.realization import DeploymentContentRealization


def _simulated_digest(reference: str) -> str:
    """Return a stable synthetic sha256 for one reference in the offline gate."""

    return "sha256:" + hashlib.sha256(reference.encode("utf-8")).hexdigest()


class _NoStartBackend(object):
    """Deployment backend stub that simulates realization without Docker.

    The static gate compiles, plans, and interprets a scenario but must never
    bring up Docker. It is an offline conformance check: it proves APTL can
    represent the typed deployment and satisfy the realization contract, not that
    containers actually run — so ``start`` is a loud error.

    Since #578, the provisioner builds its runtime snapshot from what the backend
    is *observed* to have realized (``container_inspect`` / ``host_list_networks``)
    rather than echoing the plan, and the RAES conformance probe requires that
    observed snapshot to be non-empty. This stub therefore reports back exactly
    the topology it was asked to realize — the declared node containers as running
    and healthy, the declared networks as present — so the offline conformance run
    observes a faithful realization of the scenario under test. It is a
    simulation, transparently: it fabricates no lab, and any real lifecycle call
    (``start``/``stop``/``status``) still raises.
    """

    project_name = "aptl"

    # Artifact-facing operations the deployment protocol requires (ADR-051).
    # The stub simulates realization offline, so it reports every declared
    # artifact as obtainable and materializes nothing: the static gate proves
    # the typed contract can be represented, never that bytes were fetched or
    # built. Digests are deterministic per reference so the disclosure the
    # provisioner builds is stable across runs.

    @staticmethod
    def artifact_available(
        image_ref: str, *, allow_remote: bool | None = None
    ) -> bool:
        """Report every declared artifact as obtainable in the offline gate."""

        del image_ref, allow_remote
        return True

    @staticmethod
    def materialize_component_image(
        image_ref: str, dockerfile_path: str, context_path: str
    ) -> str | None:
        """Return a deterministic stand-in digest without building anything."""

        del dockerfile_path, context_path
        return _simulated_digest(image_ref)

    @staticmethod
    def container_image_digest(container_name: str) -> str | None:
        """Return the digest the stub simulated for this container's image."""

        return _simulated_digest(container_name)

    def __init__(self) -> None:
        self._container_names: set[str] = set()
        self._network_names: list[str] = []
        self._content_root: TemporaryDirectory[str] | None = None
        self._content_paths: dict[str, Path] = {}
        self._image_free_destinations: dict[str, str] = {}

    def realize(
        self,
        realization: object,
        *,
        build: bool = True,
        scenario_root: Path | None = None,
        substrate_digests: Mapping[str, str] | None = None,
    ) -> LabResult:
        """Record the typed realization as realized without starting Docker."""
        # `build`, `scenario_root`, and `substrate_digests` are accepted for
        # DeploymentBackend parity; this offline backend builds nothing, reads no
        # scenario filesystem, and starts no base container.
        del build, scenario_root, substrate_digests
        self._container_names = {
            node.container_name
            for node in getattr(realization, "nodes", ())
            if getattr(node, "container_name", None)
        }
        # Report networks under the project-scoped name Compose actually creates
        # (`<project>_aptl-<stem>`), not the bare declared name, so the offline
        # observation exercises the same name matching a live run does.
        self._network_names = [
            _concrete_network_name(network.name, self.project_name)
            for network in getattr(realization, "networks", ())
            if getattr(network, "name", None)
        ]
        self._materialize_content_shapes(getattr(realization, "content", ()))
        return LabResult(success=True, message="Static validation realization accepted")

    def _materialize_content_shapes(self, content: Sequence[object]) -> None:
        """Create empty filesystem shapes for offline content observation.

        The static gate never copies inline or project content. It creates only
        an empty file/directory per typed realization, then the same observation
        boundary reads that filesystem state back. This keeps the offline
        simulation non-secret and non-vacuous without starting Docker.

        Image-free content (ADR-048, empty ``volume_suffix``) is read back by
        the observation layer via ``container_exec`` rather than
        ``observe_content_type``, so its destination path is additionally
        recorded under ``_image_free_destinations`` for ``container_exec`` to
        answer against.
        """

        if self._content_root is not None:
            self._content_root.cleanup()
        self._content_root = TemporaryDirectory(prefix="aptl-static-conformance-")
        root = Path(self._content_root.name)
        self._content_paths = {}
        self._image_free_destinations = {}
        for index, item in enumerate(content):
            address = getattr(item, "address", None)
            source_kind = getattr(item, "source_kind", None)
            if not isinstance(address, str):
                continue
            path = root / f"content-{index}"
            if source_kind in ("project-directory", "empty-directory"):
                path.mkdir()
                kind = "directory"
            elif source_kind in ("inline-text", "project-file"):
                path.touch()
                kind = "file"
            else:
                continue
            self._content_paths[address] = path
            dest_relpath = getattr(item, "dest_relpath", None)
            volume_suffix = getattr(item, "volume_suffix", None)
            if not volume_suffix and isinstance(dest_relpath, str):
                destination = "/" + dest_relpath.lstrip("/")
                self._image_free_destinations[destination] = kind

    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Answer the image-free content-type readback probe from simulated shapes.

        This mirrors only the ``test -d``/``test -f`` probes observation issues
        for image-free content (ADR-048); it is not a general exec simulator.
        """

        del name, timeout
        kind = self._image_free_destinations.get(cmd[-1]) if len(cmd) >= 2 else None
        matched = bool(cmd) and (
            (cmd[0:2] == ["test", "-d"] and kind == "directory")
            or (cmd[0:2] == ["test", "-f"] and kind == "file")
        )
        return subprocess.CompletedProcess(args=cmd, returncode=0 if matched else 1)

    def container_exists(self, name: str) -> bool:
        """Return whether the simulated project realized this container."""

        return name in self._container_names

    def container_inspect(self, name: str) -> dict[str, object]:
        """Report a declared node container as running and healthy.

        Only names this stub was asked to realize are reported up; anything else
        reads as absent, so the observed snapshot mirrors the declared topology
        rather than blanket-passing every probe.
        """
        if name not in self._container_names:
            return {}
        # Platform is linux because that is what APTL's Docker Compose backend
        # actually produces — every realized node is a Linux container. This is
        # the honest observed OS family, not a convenience: a node declared
        # os: windows as an EXACT concern genuinely cannot be honoured by a Linux
        # container, and the conformance gate rejecting that is correct behaviour,
        # here as in a live run.
        return {
            "State": {"Running": True, "Health": {"Status": "healthy"}},
            "Platform": "linux",
            "NetworkSettings": {"Networks": {}},
        }

    def host_list_lab_networks(self, name_prefix: str) -> list[str]:
        """Report the declared scenario networks as present, project-scoped.

        Filters by ``name_prefix`` exactly as the real backend does, so the stub
        honours the same project scoping the observer relies on.
        """
        return [name for name in self._network_names if name_prefix in name]

    def observe_content_type(
        self,
        content: "DeploymentContentRealization",
    ) -> str | None:
        """Read the filesystem kind materialized by the offline simulation."""

        path = self._content_paths.get(content.address)
        observed: str | None = None
        if path is not None:
            if path.is_file():
                observed = "file"
            elif path.is_dir():
                observed = "directory"
        return observed

    @staticmethod
    def start(profiles: list[str], *, build: bool = True) -> LabResult:
        """Refuse to start the lab from a static validation gate."""
        raise RuntimeError("static validation gate must not start the lab")

    @staticmethod
    def stop(*args: object, **kwargs: object) -> LabResult:
        """Refuse to stop the lab from a static validation gate."""
        raise RuntimeError("static validation gate must not stop the lab")

    @staticmethod
    def status() -> LabStatus:
        """Refuse to query lab status from a static validation gate."""
        raise RuntimeError("static validation gate does not query lab status")
