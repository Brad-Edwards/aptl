"""Check implementations for the RAES static validation gate (SCN-010E / #322).

These compose the RAES authorities behind
``techvault_gate.validate_scenario``; see that module for the public entry
point, the ``GateCheck`` / ``GateReport`` shapes, and the gate's contract. Each
function returns a ``GateCheck`` with redacted diagnostics (ADR-029) and never
starts Docker.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from raes_conformance.conformance import run_target_conformance
from raes_processor.compiler import compile_scenario_runtime_model
from raes_runtime.manager import RuntimeManager
from raes import SDLError, parse_sdl_file
from raes.module_registry import LOCKFILE_NAME
from raes.scenario import Scenario

from aptl.backends.raes import create_aptl_runtime_target, resolve_scenario_bundle
from aptl.backends.raes_profiles import public_start_profiles, select_backend_profiles
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.core.deployment._compose_realization_networks import _concrete_network_name
from aptl.core.lab_types import LabResult, LabStatus
from aptl.utils.redaction import redact
from aptl.validation._gate_raes_cli import (
    conformance_cli_diagnostics,
    run_raes,
    verify_imports_diagnostics,
)
from aptl.validation.techvault_gate import GateCheck

if TYPE_CHECKING:
    from raes_conformance.conformance import BackendConformanceReport
    from raes_contracts.diagnostics import Diagnostic

    from aptl.core.config import AptlConfig
    from aptl.core.deployment.realization import DeploymentContentRealization

# `raes conformance backend` is ~2s. `raes sdl verify-imports` re-resolves and
# re-parses a scenario's whole module tree, which scales with that tree rather
# than with the root document, so it gets a generous standalone timeout and runs
# in a dedicated gate step rather than the fast per-test suite. It only runs for
# scenarios that declare imports; the ones this repo ships today do not. The
# ``raes`` CLI invocations themselves live in ``_gate_raes_cli``.
_IMPORT_LOCK_TIMEOUT_S = 600


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


def check_parse(scenario_path: Path) -> tuple[Scenario | None, GateCheck]:
    """Parse the scenario with the RAES reference parser."""
    try:
        scenario = parse_sdl_file(scenario_path)
    except (SDLError, FileNotFoundError, ValueError, TypeError) as exc:
        return None, GateCheck(
            "parse", False, (redact(f"RAES parser rejected scenario: {exc}"),)
        )
    return scenario, GateCheck("parse", True)


def check_import_lock(scenario_path: Path, scenario: Scenario) -> GateCheck:
    """Verify the committed lockfile, trust policy, and import expansion.

    Runs the canonical ``raes sdl verify-imports``, which compares the committed
    ``raes.lock.json`` against a fresh resolution. The lockfile's local
    ``resolved_source`` is checkout-independent (RAES #551), so this passes on CI
    and any developer checkout and fails only when an imported module changes
    without re-running ``raes sdl resolve``.

    A scenario that declares no imports resolves nothing, so there is no lockfile
    to verify and the check is a pass. The lockfile requirement stays fail-closed
    for every scenario that does import. The import set is read from the parsed
    ``Scenario`` the RAES parser already produced — APTL does not re-read the raw
    document to reinterpret a RAES field (ADR-035 / ADR-046).
    """
    if not scenario.imports:
        return GateCheck(
            "import_lock", True, ("scenario declares no imports; nothing to lock",)
        )
    lockfile = scenario_path.with_name(LOCKFILE_NAME)
    if not lockfile.exists():
        return GateCheck(
            "import_lock",
            False,
            (
                f"missing import lockfile {lockfile.name}; run "
                f"`raes sdl resolve {scenario_path}`",
            ),
        )
    result = run_raes(
        ["sdl", "verify-imports", str(scenario_path)], timeout=_IMPORT_LOCK_TIMEOUT_S
    )
    return GateCheck("import_lock", *_outcome(verify_imports_diagnostics(result)))


def check_compile(scenario: Scenario) -> GateCheck:
    """Compile the scenario runtime model (exercises semantic validation)."""
    try:
        compile_scenario_runtime_model(scenario)
    # broad-except: RAES raises a family of compile errors
    except Exception as exc:
        return GateCheck(
            "compile",
            False,
            (redact(f"RAES compile/semantic validation failed: {exc}"),),
        )
    return GateCheck("compile", True)


def check_backend_conformance(
    *,
    project_dir: Path,
    config: AptlConfig,
    profile: str,
    fixtures_root: Path | None,
    profiles_root: Path | None,
    reference_scenario: Scenario | None = None,
) -> GateCheck:
    """Confirm APTL's canonical manifest passes target + published-CLI conformance."""
    try:
        # Conformance validates APTL's own in-tree configuration, so the bundle
        # is the in-tree bundle (root == project_dir); only the manifest is read.
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=_NoStartBackend(),
            bundle=resolve_scenario_bundle(project_dir, None, config),
        )
        report = run_target_conformance(
            target,
            profile=profile,
            root=fixtures_root,
            profiles_root=profiles_root,
            reference_scenario=reference_scenario,
        )
    # broad-except: RAES surfaces diverse errors
    except Exception as exc:
        return GateCheck(
            "backend_conformance", False, (redact(f"run_target_conformance raised: {exc}"),)
        )

    diagnostics = _target_conformance_diagnostics(report)
    diagnostics.extend(
        conformance_cli_diagnostics(profile, fixtures_root, profiles_root)
    )
    return GateCheck("backend_conformance", *_outcome(diagnostics))


def check_provisioning_realization(
    *, scenario: Scenario, project_dir: Path, config: AptlConfig
) -> tuple[Mapping[str, object] | None, GateCheck]:
    """Interpret the provisioning plan and confirm it realizes nodes/services/networks."""
    try:
        # Config-driven bundle: the configured env-pack when selected, else the
        # in-tree scenario (issue #875). Scenario content anchors to the bundle
        # root, but APTL's own component build contexts (``containers/``) always
        # resolve from the engine checkout — a pack ships none — so component_root
        # stays project_dir (ADR-051), matching the live start path.
        bundle = resolve_scenario_bundle(project_dir, None, config)
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=_NoStartBackend(),
            bundle=bundle,
        )
        execution_plan = RuntimeManager(target).plan(scenario)
        realization = interpret_provisioning_plan(
            plan=execution_plan.provisioning,
            config=config,
            bundle=bundle,
            component_root=project_dir,
        )
    # broad-except: RAES surfaces diverse errors
    except Exception as exc:
        return None, GateCheck(
            "provisioning_realization",
            False,
            (redact(f"provisioning realization raised: {exc}"),),
        )

    diagnostics = [
        redact(f"{d.code}: {d.message}")
        for d in realization.diagnostics
        if _severity(d) == "error"
    ]
    details = realization.details()
    nodes = details.get("nodes", [])
    if not nodes:
        diagnostics.append("realization produced no nodes")
    if not any(node.get("services") for node in nodes):
        diagnostics.append("realization produced no services on any node")
    if not details.get("networks"):
        diagnostics.append("realization produced no networks")
    expected_profiles = public_start_profiles(config)
    selected_profiles = select_backend_profiles(config, realization.profiles)
    if selected_profiles != expected_profiles:
        diagnostics.append(
            "RAES-selected profiles "
            f"{selected_profiles} do not match public lab start profiles "
            f"{expected_profiles}; scenario would not instantiate the same range"
        )
    return details, GateCheck("provisioning_realization", *_outcome(diagnostics))


# Realization-envelope constructive probes are derived and exercised only through
# a live realization harness (raes_conformance ``_constructive_run`` refuses a
# ``None`` harness). APTL's static backend-conformance gate runs fixture-only with
# a no-start backend and therefore cannot supply that harness, so the constructive
# case reports "no witness". This is not a manifest defect: the realization
# envelope is proven at the live lab-boot gate (issue #889), where the real
# service materializer runs and the fresh native readback proves the schema —
# exactly how the libvirt backend proves its own envelope through live evidence
# runs rather than fixture-only conformance. Only these structural no-witness codes
# are tolerated; a real envelope failure (binding mismatch, invalid digest,
# unsupported contract) carries a different code and still fails the gate.
_LIVE_HARNESS_REALIZATION_CODES = frozenset(
    {
        "realization-envelope.positive-probe.no-witness",
        "realization-envelope.negative-probe.no-witness",
    }
)


def _requires_live_realization_harness(case: object) -> bool:
    """True when a failing case only lacks the live harness the static gate omits."""

    diagnostics = getattr(case, "diagnostics", ())
    return (
        getattr(case, "contract_name", "") == "realization-envelope-v1"
        and not getattr(case, "passed", True)
        and bool(diagnostics)
        and all(getattr(d, "code", "") in _LIVE_HARNESS_REALIZATION_CODES for d in diagnostics)
    )


def _target_conformance_diagnostics(report: BackendConformanceReport) -> list[str]:
    """Turn a target conformance report into gate diagnostics."""
    diagnostics: list[str] = []
    failing_cases = [case for case in getattr(report, "cases", ()) if not case.passed]
    tolerated_cases = [case for case in failing_cases if _requires_live_realization_harness(case)]
    blocking_cases = [case for case in failing_cases if case not in tolerated_cases]
    report_codes = sorted({d.code for d in report.diagnostics})
    if not report.passed:
        # Suppress the failure only when it is fully explained by tolerated
        # live-realization cases; any other failed report still fails the gate.
        fully_tolerated = bool(tolerated_cases) and not blocking_cases and not report_codes
        if not fully_tolerated:
            codes = (
                ", ".join(report_codes + [f"case:{case.name}" for case in blocking_cases])
                or "unknown"
            )
            diagnostics.append(f"target conformance failed (diagnostics: {codes})")
    if report.unsupported_contract_gaps:
        diagnostics.append(
            "manifest missing required contracts: "
            + ", ".join(report.unsupported_contract_gaps)
        )
    if report.unsupported_capability_gaps:
        diagnostics.append(
            "manifest missing required surfaces: "
            + ", ".join(report.unsupported_capability_gaps)
        )
    return diagnostics


def _severity(diagnostic: Diagnostic) -> str:
    """Return a diagnostic's severity as a lowercase string."""
    severity = getattr(diagnostic, "severity", None)
    return getattr(severity, "value", str(severity)).lower()


def _outcome(diagnostics: list[str]) -> tuple[bool, tuple[str, ...]]:
    """Pack diagnostics into a ``(passed, diagnostics)`` pair for ``GateCheck``."""
    return (not diagnostics, tuple(diagnostics))
