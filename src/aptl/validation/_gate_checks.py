"""Check implementations for the RAES static validation gate (SCN-010E / #322).

These compose the RAES authorities behind
``techvault_gate.validate_scenario``; see that module for the public entry
point, the ``GateCheck`` / ``GateReport`` shapes, and the gate's contract. Each
function returns a ``GateCheck`` with redacted diagnostics (ADR-029) and never
starts Docker.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from raes_conformance.conformance import run_target_conformance
from raes_processor.compiler import compile_scenario_runtime_model
from raes import SDLError, instantiate_scenario, parse_sdl_file
from raes.module_registry import LOCKFILE_NAME
from raes.scenario import Scenario

from aptl.backends.raes import create_aptl_runtime_target, resolve_scenario_bundle
from aptl.backends.raes_artifact_availability import (
    artifact_availability_for_scenario,
)
from aptl.backends._raes_conformance_probe import APTL_TARGET_CONFORMANCE_SCENARIO
from aptl.backends.raes_planning_compat import plan_aptl_scenario
from aptl.backends.raes_profiles import public_start_profiles, select_backend_profiles
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.core.scenario_bundle import project_tree_bundle
from aptl.utils.redaction import redact
from aptl.validation._gate_no_start_backend import _NoStartBackend
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

# `raes conformance backend` is ~2s. `raes sdl verify-imports` re-resolves and
# re-parses a scenario's whole module tree, which scales with that tree rather
# than with the root document, so it gets a generous standalone timeout and runs
# in a dedicated gate step rather than the fast per-test suite. It only runs for
# scenarios that declare imports; the ones this repo ships today do not. The
# ``raes`` CLI invocations themselves live in ``_gate_raes_cli``.
_IMPORT_LOCK_TIMEOUT_S = 600


def _static_validation_scenario(scenario: Scenario) -> Scenario:
    """Instantiate required variables with typed, non-runtime witness values.

    A static gate proves that a scenario can compile; it does not choose the
    values of a future run.  Required variables without defaults therefore use
    deterministic type-correct witnesses here.  Live admission still requires
    an explicit owner for every real binding.
    """

    values: dict[str, object] = {}
    witnesses: dict[str, object] = {
        "string": "aptl-static-validation-value",
        "integer": 0,
        "number": 0,
        "boolean": False,
    }
    for name, variable in scenario.variables.items():
        if not variable.required or variable.default is not None:
            continue
        values[name] = (
            variable.allowed_values[0]
            if variable.allowed_values
            else witnesses[str(getattr(variable.type, "value", variable.type))]
        )
    return instantiate_scenario(scenario, values) if values else scenario


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
        compile_scenario_runtime_model(_static_validation_scenario(scenario))
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
    """Confirm APTL's canonical manifest passes target + published-CLI conformance.

    The target-adapter corpus is hermetic and intentionally uses RAES's own
    probe scenario.  Admission of the caller's scenario is a separate gate in
    :func:`check_provisioning_realization`, where APTL can provide the trusted
    artifact-availability facts that a real plan requires.  Feeding the caller's
    scenario to ``run_target_conformance`` would make the adapter probe reject
    exact artifacts solely because that API has no availability input.
    """
    del reference_scenario
    try:
        # Conformance validates APTL's own in-tree configuration, so the bundle
        # is the in-tree bundle (root == project_dir); only the manifest is read.
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=_NoStartBackend(),
            bundle=project_tree_bundle(
                project_dir,
                project_dir / "scenarios" / "conformance-probe.sdl.yaml",
            ),
        )
        report = run_target_conformance(
            target,
            profile=profile,
            root=fixtures_root,
            profiles_root=profiles_root,
            reference_scenario=APTL_TARGET_CONFORMANCE_SCENARIO,
        )
    # broad-except: RAES surfaces diverse errors
    except Exception as exc:
        return GateCheck(
            "backend_conformance",
            False,
            (redact(f"run_target_conformance raised: {exc}"),),
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
        backend = _NoStartBackend()
        static_scenario = _static_validation_scenario(scenario)
        availability = artifact_availability_for_scenario(
            static_scenario,
            backend,
            scenario_root=bundle.root,
            component_root=project_dir,
        )
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=backend,
            bundle=bundle,
            artifact_availability=availability,
        )
        execution_plan = plan_aptl_scenario(
            target=target,
            bundle=bundle,
            scenario=static_scenario,
            artifact_availability=availability,
        )
        planning_diagnostics = [
            redact(f"{d.code}: {d.message}")
            for d in execution_plan.diagnostics
            if _severity(d) == "error"
        ]
        if planning_diagnostics:
            return None, GateCheck(
                "provisioning_realization",
                False,
                tuple(planning_diagnostics),
            )
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
        and all(
            getattr(d, "code", "") in _LIVE_HARNESS_REALIZATION_CODES
            for d in diagnostics
        )
    )


def _report_failure_diagnostic(
    report: BackendConformanceReport,
    tolerated_cases: list[object],
    blocking_cases: list[object],
    report_codes: list[str],
) -> str | None:
    """Return the target-conformance failure diagnostic, or ``None`` if fully tolerated.

    Suppresses the failure only when it is fully explained by tolerated
    live-realization cases; any other failed report still fails the gate.
    """

    if report.passed:
        return None
    fully_tolerated = bool(tolerated_cases) and not blocking_cases and not report_codes
    if fully_tolerated:
        return None
    codes = (
        ", ".join(report_codes + [f"case:{case.name}" for case in blocking_cases])
        or "unknown"
    )
    return f"target conformance failed (diagnostics: {codes})"


def _target_conformance_diagnostics(report: BackendConformanceReport) -> list[str]:
    """Turn a target conformance report into gate diagnostics."""
    diagnostics: list[str] = []
    failing_cases = [case for case in getattr(report, "cases", ()) if not case.passed]
    tolerated_cases = [
        case for case in failing_cases if _requires_live_realization_harness(case)
    ]
    blocking_cases = [case for case in failing_cases if case not in tolerated_cases]
    report_codes = sorted({d.code for d in report.diagnostics})
    failure = _report_failure_diagnostic(
        report, tolerated_cases, blocking_cases, report_codes
    )
    if failure is not None:
        diagnostics.append(failure)
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
