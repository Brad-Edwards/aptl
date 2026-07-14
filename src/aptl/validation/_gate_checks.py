"""Check implementations for the ACES static validation gate (SCN-010E / #322).

These compose the ACES authorities behind
``techvault_gate.validate_scenario``; see that module for the public entry
point, the ``GateCheck`` / ``GateReport`` shapes, and the gate's contract. Each
function returns a ``GateCheck`` with redacted diagnostics (ADR-029) and never
starts Docker.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from aces_conformance.conformance import run_target_conformance
from aces_processor.compiler import compile_scenario_runtime_model
from aces_runtime.manager import RuntimeManager
from aces_sdl import SDLError, parse_sdl_file
from aces_sdl.scenario import Scenario

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_profiles import public_start_profiles, select_backend_profiles
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.deployment._compose_realization_networks import _concrete_network_name
from aptl.core.lab_types import LabResult, LabStatus
from aptl.utils.redaction import redact
from aptl.validation.techvault_gate import GateCheck

if TYPE_CHECKING:
    from aces_conformance.conformance import BackendConformanceReport
    from aces_contracts.diagnostics import Diagnostic

    from aptl.core.config import AptlConfig

# `aces conformance backend` is ~2s. `aces sdl verify-imports` re-resolves and
# re-parses a scenario's whole module tree, which scales with that tree rather
# than with the root document, so it gets a generous standalone timeout and runs
# in a dedicated gate step rather than the fast per-test suite. It only runs for
# scenarios that declare imports; the ones this repo ships today do not.
_SUBPROCESS_TIMEOUT_S = 120
_IMPORT_LOCK_TIMEOUT_S = 600


class _NoStartBackend(object):
    """Deployment backend stub that simulates realization without Docker.

    The static gate compiles, plans, and interprets a scenario but must never
    bring up Docker. It is an offline conformance check: it proves APTL can
    represent the typed deployment and satisfy the realization contract, not that
    containers actually run — so ``start`` is a loud error.

    Since #578, the provisioner builds its runtime snapshot from what the backend
    is *observed* to have realized (``container_inspect`` / ``host_list_networks``)
    rather than echoing the plan, and the ACES conformance probe requires that
    observed snapshot to be non-empty. This stub therefore reports back exactly
    the topology it was asked to realize — the declared node containers as running
    and healthy, the declared networks as present — so the offline conformance run
    observes a faithful realization of the scenario under test. It is a
    simulation, transparently: it fabricates no lab, and any real lifecycle call
    (``start``/``stop``/``status``) still raises.
    """

    project_name = "aptl"

    def __init__(self) -> None:
        self._container_names: set[str] = set()
        self._network_names: list[str] = []

    def realize(self, realization: object, *, build: bool = True) -> LabResult:
        """Record the typed realization as realized without starting Docker."""
        # `build` is accepted for DeploymentBackend parity; nothing is built here.
        del build
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
        return LabResult(success=True, message="Static validation realization accepted")

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
    """Parse the scenario with the ACES reference parser."""
    try:
        scenario = parse_sdl_file(scenario_path)
    except (SDLError, FileNotFoundError, ValueError, TypeError) as exc:
        return None, GateCheck(
            "parse", False, (redact(f"ACES parser rejected scenario: {exc}"),)
        )
    return scenario, GateCheck("parse", True)


def check_import_lock(scenario_path: Path, scenario: Scenario) -> GateCheck:
    """Verify the committed lockfile, trust policy, and import expansion.

    Runs the canonical ``aces sdl verify-imports``, which compares the committed
    ``aces.lock.json`` against a fresh resolution. The lockfile's local
    ``resolved_source`` is checkout-independent (ACES #551), so this passes on CI
    and any developer checkout and fails only when an imported module changes
    without re-running ``aces sdl resolve``.

    A scenario that declares no imports resolves nothing, so there is no lockfile
    to verify and the check is a pass. The lockfile requirement stays fail-closed
    for every scenario that does import. The import set is read from the parsed
    ``Scenario`` the ACES parser already produced — APTL does not re-read the raw
    document to reinterpret an ACES field (ADR-035 / ADR-046).
    """
    if not scenario.imports:
        return GateCheck(
            "import_lock", True, ("scenario declares no imports; nothing to lock",)
        )
    lockfile = scenario_path.with_name("aces.lock.json")
    if not lockfile.exists():
        return GateCheck(
            "import_lock",
            False,
            (
                f"missing import lockfile {lockfile.name}; run "
                f"`aces sdl resolve {scenario_path}`",
            ),
        )
    result = _run_aces(
        ["sdl", "verify-imports", str(scenario_path)], timeout=_IMPORT_LOCK_TIMEOUT_S
    )
    return GateCheck("import_lock", *_outcome(_verify_imports_diagnostics(result)))


def check_compile(scenario: Scenario) -> GateCheck:
    """Compile the scenario runtime model (exercises semantic validation)."""
    try:
        compile_scenario_runtime_model(scenario)
    # broad-except: ACES raises a family of compile errors
    except Exception as exc:
        return GateCheck(
            "compile",
            False,
            (redact(f"ACES compile/semantic validation failed: {exc}"),),
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
        target = create_aptl_runtime_target(
            project_dir=project_dir, config=config, backend=_NoStartBackend()
        )
        report = run_target_conformance(
            target,
            profile=profile,
            root=fixtures_root,
            profiles_root=profiles_root,
            reference_scenario=reference_scenario,
        )
    # broad-except: ACES surfaces diverse errors
    except Exception as exc:
        return GateCheck(
            "backend_conformance", False, (redact(f"run_target_conformance raised: {exc}"),)
        )

    diagnostics = _target_conformance_diagnostics(report)
    diagnostics.extend(
        _conformance_cli_diagnostics(profile, fixtures_root, profiles_root)
    )
    return GateCheck("backend_conformance", *_outcome(diagnostics))


def check_provisioning_realization(
    *, scenario: Scenario, project_dir: Path, config: AptlConfig
) -> tuple[Mapping[str, object] | None, GateCheck]:
    """Interpret the provisioning plan and confirm it realizes nodes/services/networks."""
    try:
        target = create_aptl_runtime_target(
            project_dir=project_dir, config=config, backend=_NoStartBackend()
        )
        execution_plan = RuntimeManager(target).plan(scenario)
        realization = interpret_provisioning_plan(
            plan=execution_plan.provisioning, project_dir=project_dir, config=config
        )
    # broad-except: ACES surfaces diverse errors
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
            "ACES-selected profiles "
            f"{selected_profiles} do not match public lab start profiles "
            f"{expected_profiles}; scenario would not instantiate the same range"
        )
    return details, GateCheck("provisioning_realization", *_outcome(diagnostics))


def _target_conformance_diagnostics(report: BackendConformanceReport) -> list[str]:
    """Turn a target conformance report into gate diagnostics."""
    diagnostics: list[str] = []
    if not report.passed:
        codes = ", ".join(sorted({d.code for d in report.diagnostics})) or "unknown"
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


def _conformance_cli_diagnostics(
    profile: str, fixtures_root: Path | None, profiles_root: Path | None
) -> list[str]:
    """Run the published ``aces conformance backend`` command and report failures."""
    cli = ["conformance", "backend", "--profile", profile]
    if fixtures_root is not None:
        cli += ["--fixtures-root", str(fixtures_root)]
    if profiles_root is not None:
        cli += ["--profiles-root", str(profiles_root)]
    result = _run_aces(cli)
    if result is None:
        return ["`aces` CLI not found on PATH; conformance command is unavailable"]
    if result.returncode != 0:
        return [redact(f"aces conformance backend exited non-zero: {_cli_detail(result)}")]
    return []


def _verify_imports_diagnostics(
    result: subprocess.CompletedProcess[str] | None,
) -> list[str]:
    """Turn an ``aces sdl verify-imports`` run into gate diagnostics."""
    if result is None:
        return ["`aces` CLI not found on PATH; ACES import tooling is unavailable"]
    if result.returncode != 0:
        return [redact(f"aces sdl verify-imports failed: {_cli_detail(result)}")]
    return []


def _severity(diagnostic: Diagnostic) -> str:
    """Return a diagnostic's severity as a lowercase string."""
    severity = getattr(diagnostic, "severity", None)
    return getattr(severity, "value", str(severity)).lower()


def _outcome(diagnostics: list[str]) -> tuple[bool, tuple[str, ...]]:
    """Pack diagnostics into a ``(passed, diagnostics)`` pair for ``GateCheck``."""
    return (not diagnostics, tuple(diagnostics))


def _run_aces(
    args: Sequence[str], *, timeout: int = _SUBPROCESS_TIMEOUT_S
) -> subprocess.CompletedProcess[str] | None:
    """Run an ``aces`` subcommand, returning None when the CLI is unavailable."""
    executable = shutil.which("aces")
    if executable is None:
        return None
    # Fixed argv (resolved executable, subcommand, paths/profile), no shell;
    # S603 is a false positive for this trusted, non-interpolated invocation.
    return subprocess.run(
        [executable, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _cli_detail(result: subprocess.CompletedProcess[str]) -> str:
    """Extract a concise, structured failure detail from a conformance run."""
    payload = result.stdout.strip()
    if payload:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, Mapping):
            codes = sorted(
                {
                    d.get("code", "?")
                    for d in data.get("diagnostics", [])
                    if isinstance(d, Mapping)
                }
            )
            if codes:
                return f"exit={result.returncode} diagnostics={codes}"
    tail = (result.stderr or result.stdout or "").strip().splitlines()
    return f"exit={result.returncode} {tail[-1] if tail else ''}".strip()
