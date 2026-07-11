"""Check implementations for the ACES static validation gate (SCN-010E / #322).

These compose the ACES authorities behind
``techvault_gate.validate_scenario``; see that module for the public entry
point, the ``GateCheck`` / ``GateReport`` shapes, and the gate's contract. Each
function returns a ``GateCheck`` with redacted diagnostics (ADR-029) and never
starts Docker.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from aces_conformance.conformance import run_target_conformance
from aces_processor.compiler import compile_scenario_runtime_model
from aces_runtime.manager import RuntimeManager
from aces_sdl import SDLError, parse_sdl_file
from aces_sdl.scenario import Scenario

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_profiles import public_start_profiles, select_backend_profiles
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.lab_types import LabResult, LabStatus
from aptl.utils.redaction import redact
from aptl.validation._account_parity import (
    check_account_provisioner_parity as check_account_provisioner_parity,
)
from aptl.validation.techvault_gate import (
    DEFAULT_PARITY_INVENTORY,
    PHASE_B,
    REQUIRED_SURFACES,
    GateCheck,
)

if TYPE_CHECKING:
    from aces_conformance.conformance import BackendConformanceReport
    from aces_contracts.diagnostics import Diagnostic

    from aptl.core.config import AptlConfig

# A deferral must cite an APTL issue (``#312``) or an ACES upstream pointer
# (``aces#537``); "n/a"/"none"/empty is not a deferral.
_ISSUE_REF = re.compile(r"^(?:[a-z0-9][a-z0-9._-]*)?#\d+$", re.IGNORECASE)

# `aces conformance backend` is ~2s. `aces sdl verify-imports` re-resolves and
# re-parses TechVault's full module tree (hundreds of MB of inventory data) and
# measures ~4.5 min, so it gets a generous standalone timeout and runs in a
# dedicated gate step rather than the fast per-test suite.
_SUBPROCESS_TIMEOUT_S = 120
_IMPORT_LOCK_TIMEOUT_S = 600


class _NoStartBackend(object):
    """Deployment backend stub that refuses to start the lab.

    The static gate compiles, plans, and interprets a scenario but must never
    bring up Docker. The realization path (``provisioner.validate``) never calls
    ``start``; this stub makes an accidental lab launch a loud error instead.
    """

    @staticmethod
    def realize(realization: object, *, build: bool = True) -> LabResult:
        """Acknowledge typed realization without starting Docker.

        ACES target conformance probes submit provisioning through the runtime
        control plane and require a mutated snapshot. The static gate validates
        that APTL can interpret and represent the typed deployment, but it must
        not actually start containers.
        """
        return LabResult(success=True, message="Static validation realization accepted")

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


def check_import_lock(scenario_path: Path) -> GateCheck:
    """Verify the committed lockfile, trust policy, and import expansion.

    Runs the canonical ``aces sdl verify-imports``, which compares the committed
    ``aces.lock.json`` against a fresh resolution. The lockfile's local
    ``resolved_source`` is checkout-independent (ACES #551), so this passes on CI
    and any developer checkout and fails only when an imported module changes
    without re-running ``aces sdl resolve``.
    """
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


def check_parity_manifest(
    *,
    scenario: Scenario,
    realization_details: Mapping[str, object] | None,
    project_dir: Path,
    parity_inventory_path: Path | None,
    phase: str,
) -> GateCheck:
    """Confirm every required surface is represented with evidence or deferred."""
    inventory_path = parity_inventory_path or (project_dir / DEFAULT_PARITY_INVENTORY)
    coverage, load_error = _load_required_surface_coverage(inventory_path)
    if load_error is not None:
        return GateCheck("parity_manifest", False, (load_error,))

    diagnostics = _coverage_set_diagnostics(coverage)
    doc = scenario.model_dump(mode="json", by_alias=True)
    evidence = _surface_evidence(doc, realization_details or {})
    for surface in REQUIRED_SURFACES:
        if surface in coverage:
            diagnostics.extend(
                _surface_diagnostics(surface, coverage[surface], evidence, phase)
            )
    return GateCheck("parity_manifest", *_outcome(diagnostics))


def _load_required_surface_coverage(
    inventory_path: Path,
) -> tuple[Mapping[str, object], str | None]:
    """Load the parity inventory's ``required_surface_coverage`` mapping."""
    coverage: Mapping[str, object] = {}
    error: str | None = None
    if not inventory_path.exists():
        error = f"parity inventory missing at {inventory_path}"
    else:
        try:
            with inventory_path.open(encoding="utf-8") as handle:
                inventory = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError) as exc:
            error = redact(f"parity inventory unreadable: {exc}")
        else:
            top = inventory if isinstance(inventory, Mapping) else {}
            loaded = top.get("required_surface_coverage")
            if isinstance(loaded, Mapping):
                coverage = loaded
            else:
                error = "parity inventory has no `required_surface_coverage` mapping"
    return coverage, error


def _coverage_set_diagnostics(coverage: Mapping[str, object]) -> list[str]:
    """Report required surfaces missing from, or unknown to, the coverage map."""
    diagnostics: list[str] = []
    missing = set(REQUIRED_SURFACES) - set(coverage)
    extra = set(coverage) - set(REQUIRED_SURFACES)
    if missing:
        diagnostics.append(f"surface coverage missing entries: {sorted(missing)}")
    if extra:
        diagnostics.append(f"surface coverage has unknown entries: {sorted(extra)}")
    return diagnostics


def _surface_diagnostics(
    surface: str, entry: object, evidence: Mapping[str, bool], phase: str
) -> list[str]:
    """Validate one surface coverage entry, failing closed on malformed input."""
    if not isinstance(entry, Mapping):
        return [
            f"surface {surface!r} coverage entry must be a mapping, "
            f"got {type(entry).__name__}"
        ]
    status = entry.get("status")
    diagnostics: list[str] = []
    if status == "represented":
        if not evidence.get(surface):
            diagnostics.append(
                f"surface {surface!r} marked represented but the compiled "
                f"scenario carries no evidence for it"
            )
    elif status == "deferred":
        followup = str(entry.get("blocking_followup", "")).strip()
        if not _ISSUE_REF.match(followup):
            diagnostics.append(
                f"surface {surface!r} deferred without a tracking issue "
                f"(blocking_followup={followup!r})"
            )
        elif phase == PHASE_B:
            diagnostics.append(
                f"surface {surface!r} is deferred ({followup}); Phase B "
                f"cutover requires full representation"
            )
    else:
        diagnostics.append(
            f"surface {surface!r} has invalid status {status!r} "
            f"(expected 'represented' or 'deferred')"
        )
    return diagnostics


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


def _surface_evidence(
    doc: Mapping[str, object], realization_details: Mapping[str, object]
) -> dict[str, bool]:
    """Detect which required surfaces carry real compiled/realized evidence."""
    nodes = realization_details.get("nodes", [])
    profiles = set(realization_details.get("profiles", []))
    return {
        "nodes": bool(nodes),
        "services": any(node.get("services") for node in nodes),
        "vulnerabilities": bool(doc.get("vulnerabilities")),
        "features": bool(doc.get("features")),
        "kali_apparatus": "kali" in profiles,
        "defensive_stack": bool({"soc", "wazuh"} & profiles),
        "health": _contains_key(doc.get("nodes"), "health"),
    }


def _contains_key(obj: object, key: str) -> bool:
    """Recursively test whether ``key`` appears as a mapping key in ``obj``."""
    if isinstance(obj, Mapping):
        return key in obj or any(_contains_key(value, key) for value in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_contains_key(item, key) for item in obj)
    return False


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
