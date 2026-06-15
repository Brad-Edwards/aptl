"""Static validation gate for ACES scenarios (SCN-010E / issue #322).

Composes the ACES authorities — the reference parser, import-lock verification,
the runtime compiler/semantic validator, and canonical ``backend-manifest-v2``
conformance — together with APTL's provisioning realization and the parity
inventory into a single, scenario-generic gate. It is parameterized by scenario
path, backend profile, corpus roots, and target name: TechVault is the proving
input, never a hardcoded branch, so the next scenario in APTL's expressivity
class passes through by changing inputs rather than editing this module.

The gate is STATIC. It parses, locks, compiles, conformance-checks, and
interprets the provisioning plan, but never starts Docker or touches the lab
(``_NoStartBackend`` refuses ``start``). Every failure is a structured, redacted
diagnostic; the gate never emits the full SDL object or a raw exception payload
(ADR-029).

A missing ACES contract corpus, profile artifact, or conformance CLI is a gate
*failure* with an actionable diagnostic — never silently downgraded to a
warning, and never a reason to accept an APTL-local manifest approximation.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from aces_conformance.conformance import run_target_conformance
from aces_processor.compiler import compile_scenario_runtime_model
from aces_runtime.manager import RuntimeManager
from aces_sdl import SDLError, parse_sdl_file

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.lab_types import LabResult, LabStatus
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig

DEFAULT_PROFILE = "provisioning-only"
DEFAULT_SCENARIO = Path("scenarios") / "techvault.sdl.yaml"
DEFAULT_PARITY_INVENTORY = Path("docs") / "aces" / "parity-inventory.yaml"

PHASE_A = "phase_a"
PHASE_B = "phase_b"

# Observable surface families SCN-010E requires the gate to account for. Each
# must be REPRESENTED with real compiled evidence, or explicitly DEFERRED with a
# linked tracking issue in the parity inventory. The set is the checker's
# contract — a silently dropped surface fails the gate.
REQUIRED_SURFACES: tuple[str, ...] = (
    "nodes",
    "services",
    "vulnerabilities",
    "features",
    "injects",
    "workflows",
    "objectives",
    "scoring",
    "run_archive",
    "kali_apparatus",
    "defensive_stack",
    "health",
)

# A deferral must cite an APTL issue (``#312``) or an ACES upstream pointer
# (``aces#537``); "n/a"/"none"/empty is not a deferral.
_ISSUE_REF = re.compile(r"^(?:[a-z0-9][a-z0-9._-]*)?#\d+$", re.IGNORECASE)

# `aces conformance backend` is ~2s. `aces sdl verify-imports` re-resolves and
# re-parses TechVault's full module tree (hundreds of MB of inventory data) and
# measures ~4.5 min, so it gets a generous standalone timeout and runs in a
# dedicated gate step rather than the fast per-test suite (see the check_imports
# flag on validate_scenario).
_SUBPROCESS_TIMEOUT_S = 120
_IMPORT_LOCK_TIMEOUT_S = 600


@dataclass(frozen=True)
class GateCheck:
    """One named gate check and its outcome."""

    name: str
    passed: bool
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateReport:
    """The composed outcome of every gate check for a scenario."""

    scenario: str
    profile: str
    phase: str
    checks: tuple[GateCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def failures(self) -> tuple[GateCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)

    def render(self) -> str:
        """Render a redacted, human/CI-readable summary."""
        lines = [
            f"ACES static validation gate — scenario={self.scenario} "
            f"profile={self.profile} phase={self.phase}: "
            f"{'PASS' if self.passed else 'FAIL'}"
        ]
        for check in self.checks:
            marker = "ok" if check.passed else "FAIL"
            lines.append(f"  [{marker}] {check.name}")
            for diagnostic in check.diagnostics:
                lines.append(f"        - {diagnostic}")
        return "\n".join(lines)


class _NoStartBackend:
    """Deployment backend stub that refuses to start the lab.

    The static gate compiles, plans, and interprets a scenario but must never
    bring up Docker. The realization path (``provisioner.validate``) never calls
    ``start``; this stub makes an accidental lab launch a loud error instead.
    """

    def start(self, profiles: list[str], *, build: bool = True) -> LabResult:
        raise RuntimeError("static validation gate must not start the lab")

    def stop(self, *args: Any, **kwargs: Any) -> LabResult:
        raise RuntimeError("static validation gate must not stop the lab")

    def status(self) -> LabStatus:
        raise RuntimeError("static validation gate does not query lab status")


def validate_scenario(
    scenario_path: Path,
    *,
    project_dir: Path,
    config: "AptlConfig",
    profile: str = DEFAULT_PROFILE,
    fixtures_root: Path | None = None,
    profiles_root: Path | None = None,
    parity_inventory_path: Path | None = None,
    phase: str = PHASE_A,
    check_imports: bool = True,
) -> GateReport:
    """Run the full static validation gate for ``scenario_path``.

    Returns a :class:`GateReport`. ``fixtures_root`` / ``profiles_root`` override
    the ACES corpus roots (default: the published roots bundled with the
    installed ``aces-sdl`` wheel). ``phase`` selects Phase A (deferrals allowed
    when issue-linked) or Phase B cutover (deferrals disallowed).

    ``check_imports`` controls the slow ``aces sdl verify-imports`` step
    (~4.5 min on TechVault). It defaults to True (complete gate, as run by the
    dedicated CI job / pre-push hook); the fast inner-loop test suite passes
    ``check_imports=False`` and lets the dedicated step own lock verification.
    """
    checks: list[GateCheck] = []

    # 1. Parse — ACES reference parser must accept the scenario.
    scenario, parse_check = _check_parse(scenario_path)
    checks.append(parse_check)
    if scenario is None:
        return GateReport(str(scenario_path), profile, phase, tuple(checks))

    # 2. Import lock — verify the committed lockfile, trust policy, and imports.
    if check_imports:
        checks.append(_check_import_lock(scenario_path))

    # 3. Compile / semantic validation — produce the runtime model.
    runtime_model, compile_check = _check_compile(scenario)
    checks.append(compile_check)

    # 4. Backend manifest + conformance (API target check + published CLI).
    checks.append(
        _check_backend_conformance(
            project_dir=project_dir,
            config=config,
            profile=profile,
            fixtures_root=fixtures_root,
            profiles_root=profiles_root,
        )
    )

    # 5. Provisioning realization — interpret the plan, scenario-generically.
    realization_details, realization_check = _check_provisioning_realization(
        scenario=scenario,
        project_dir=project_dir,
        config=config,
    )
    checks.append(realization_check)

    # 6. Parity manifest — every required surface represented or deferred.
    checks.append(
        _check_parity_manifest(
            scenario=scenario,
            runtime_model=runtime_model,
            realization_details=realization_details,
            project_dir=project_dir,
            parity_inventory_path=parity_inventory_path,
            phase=phase,
        )
    )

    return GateReport(str(scenario_path), profile, phase, tuple(checks))


def _check_parse(scenario_path: Path) -> tuple[Any | None, GateCheck]:
    try:
        scenario = parse_sdl_file(scenario_path)
    except (SDLError, FileNotFoundError, ValueError, TypeError) as exc:
        return None, GateCheck(
            "parse", False, (redact(f"ACES parser rejected scenario: {exc}"),)
        )
    return scenario, GateCheck("parse", True)


def _check_import_lock(scenario_path: Path) -> GateCheck:
    """Verify the committed lockfile, trust policy, and import expansion.

    Runs the canonical `aces sdl verify-imports`, which compares the committed
    `aces.lock.json` against a fresh resolution. The lockfile's local
    `resolved_source` is checkout-independent (ACES #551), so this passes on CI
    and any developer checkout and fails only when an imported module changes
    without re-running `aces sdl resolve`.
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
    if result is None:
        return GateCheck(
            "import_lock",
            False,
            ("`aces` CLI not found on PATH; ACES import tooling is unavailable",),
        )
    if result.returncode != 0:
        return GateCheck(
            "import_lock",
            False,
            (redact(f"aces sdl verify-imports failed: {_cli_detail(result)}"),),
        )
    return GateCheck("import_lock", True)


def _check_compile(scenario: Any) -> tuple[Any | None, GateCheck]:
    try:
        runtime_model = compile_scenario_runtime_model(scenario)
    except Exception as exc:  # noqa: BLE001 — ACES raises a family of compile errors
        return None, GateCheck(
            "compile", False, (redact(f"ACES compile/semantic validation failed: {exc}"),)
        )
    return runtime_model, GateCheck("compile", True)


def _check_backend_conformance(
    *,
    project_dir: Path,
    config: "AptlConfig",
    profile: str,
    fixtures_root: Path | None,
    profiles_root: Path | None,
) -> GateCheck:
    diagnostics: list[str] = []

    # 4a. API: APTL's canonical manifest/target passes target conformance.
    try:
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=_NoStartBackend(),
        )
        report = run_target_conformance(
            target,
            profile=profile,
            root=fixtures_root,
            profiles_root=profiles_root,
        )
    except Exception as exc:  # noqa: BLE001
        return GateCheck(
            "backend_conformance",
            False,
            (redact(f"run_target_conformance raised: {exc}"),),
        )
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

    # 4b. CLI: the published `aces conformance backend` command + corpus run.
    cli = ["conformance", "backend", "--profile", profile]
    if fixtures_root is not None:
        cli += ["--fixtures-root", str(fixtures_root)]
    if profiles_root is not None:
        cli += ["--profiles-root", str(profiles_root)]
    result = _run_aces(cli)
    if result is None:
        diagnostics.append(
            "`aces` CLI not found on PATH; conformance command is unavailable"
        )
    elif result.returncode != 0:
        diagnostics.append(
            redact(f"aces conformance backend exited non-zero: {_cli_detail(result)}")
        )

    return GateCheck("backend_conformance", not diagnostics, tuple(diagnostics))


def _check_provisioning_realization(
    *,
    scenario: Any,
    project_dir: Path,
    config: "AptlConfig",
) -> tuple[Mapping[str, Any] | None, GateCheck]:
    try:
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=_NoStartBackend(),
        )
        execution_plan = RuntimeManager(target).plan(scenario)
        realization = interpret_provisioning_plan(
            plan=execution_plan.provisioning,
            project_dir=project_dir,
            config=config,
        )
    except Exception as exc:  # noqa: BLE001
        return None, GateCheck(
            "provisioning_realization",
            False,
            (redact(f"provisioning realization raised: {exc}"),),
        )

    diagnostics: list[str] = []
    errors = [
        d for d in realization.diagnostics if _severity(d) == "error"
    ]
    for diagnostic in errors:
        diagnostics.append(redact(f"{diagnostic.code}: {diagnostic.message}"))

    details = realization.details()
    nodes = details.get("nodes", [])
    if not nodes:
        diagnostics.append("realization produced no nodes")
    if not any(node.get("services") for node in nodes):
        diagnostics.append("realization produced no services on any node")
    if not details.get("networks"):
        diagnostics.append("realization produced no networks")

    return details, GateCheck(
        "provisioning_realization", not diagnostics, tuple(diagnostics)
    )


def _check_parity_manifest(
    *,
    scenario: Any,
    runtime_model: Any | None,
    realization_details: Mapping[str, Any] | None,
    project_dir: Path,
    parity_inventory_path: Path | None,
    phase: str,
) -> GateCheck:
    inventory_path = parity_inventory_path or (project_dir / DEFAULT_PARITY_INVENTORY)
    if not inventory_path.exists():
        return GateCheck(
            "parity_manifest",
            False,
            (f"parity inventory missing at {inventory_path}",),
        )
    try:
        with inventory_path.open(encoding="utf-8") as handle:
            inventory = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        return GateCheck(
            "parity_manifest", False, (redact(f"parity inventory unreadable: {exc}"),)
        )

    coverage = (inventory or {}).get("required_surface_coverage")
    if not isinstance(coverage, Mapping):
        return GateCheck(
            "parity_manifest",
            False,
            ("parity inventory has no `required_surface_coverage` mapping",),
        )

    diagnostics: list[str] = []
    missing = set(REQUIRED_SURFACES) - set(coverage)
    extra = set(coverage) - set(REQUIRED_SURFACES)
    if missing:
        diagnostics.append(f"surface coverage missing entries: {sorted(missing)}")
    if extra:
        diagnostics.append(f"surface coverage has unknown entries: {sorted(extra)}")

    doc = scenario.model_dump(mode="json", by_alias=True)
    evidence = _surface_evidence(doc, realization_details or {})

    for surface in REQUIRED_SURFACES:
        if surface not in coverage:
            continue  # already reported by the `missing` check above
        entry = coverage[surface]
        if not isinstance(entry, Mapping):
            # Fail closed: a non-mapping entry (scalar/list/null) is not a valid
            # coverage declaration and must not silently bypass validation.
            diagnostics.append(
                f"surface {surface!r} coverage entry must be a mapping, "
                f"got {type(entry).__name__}"
            )
            continue
        status = entry.get("status")
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

    return GateCheck("parity_manifest", not diagnostics, tuple(diagnostics))


def _surface_evidence(
    doc: Mapping[str, Any], realization_details: Mapping[str, Any]
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


def _contains_key(obj: Any, key: str) -> bool:
    """Recursively test whether ``key`` appears as a mapping key in ``obj``."""
    if isinstance(obj, Mapping):
        if key in obj:
            return True
        return any(_contains_key(value, key) for value in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_contains_key(item, key) for item in obj)
    return False


def _severity(diagnostic: Any) -> str:
    severity = getattr(diagnostic, "severity", None)
    return getattr(severity, "value", str(severity)).lower()


def _run_aces(
    args: Sequence[str], *, timeout: int = _SUBPROCESS_TIMEOUT_S
) -> subprocess.CompletedProcess[str] | None:
    """Run an ``aces`` subcommand, returning None when the CLI is unavailable."""
    executable = shutil.which("aces")
    if executable is None:
        return None
    return subprocess.run(  # noqa: S603 — fixed argv, paths/profile only, no shell
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
                {d.get("code", "?") for d in data.get("diagnostics", []) if isinstance(d, Mapping)}
            )
            if codes:
                return f"exit={result.returncode} diagnostics={codes}"
    tail = (result.stderr or result.stdout or "").strip().splitlines()
    return f"exit={result.returncode} {tail[-1] if tail else ''}".strip()
