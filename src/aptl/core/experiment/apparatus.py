"""Apparatus admission and planning-only feasibility (ADR-047 "Apparatus and
capture capability admission").

Two independent surfaces live here:

* :func:`check_apparatus_admission` — a CONJUNCTIVE admission gate over
  ``ExperimentTaskModel.apparatus_constraints`` and the authoring input's
  optional ``apparatus_intent`` (the same ``ExperimentApparatusConstraintModel``
  shape). It rejects (raises :class:`~aptl.core.experiment.errors.AdmissionRejection`)
  on ANY incompatibility:

  - ``apparatus_intent`` may only NARROW the task's constraints, never
    weaken or expand them. Naming a processor/backend/capability the task
    does not allow is rejected.
  - Every allowed processor/backend identity actually being used for this
    admission (the resolved manifests — ``create_aptl_manifest()`` and
    ``create_reference_processor_manifest()`` by default; injectable for
    tests) must appear in the applicable allow-list, when that allow-list
    is non-empty. An EMPTY allow-list on one axis (e.g. no
    ``allowed_backend_refs``) means the task did not restrict THAT axis —
    it is not a global "allow anything" escape, because
    ``ExperimentApparatusConstraintModel`` itself requires at least one of
    its five fields to be non-empty.
  - ``required_manifest_refs`` naming a processor/backend subject must pin
    the correct contract-version literal (``processor-manifest/v2`` /
    ``backend-manifest/v2`` — the SLASH form; never compared against a
    ``supported_contract_versions`` HYPHEN entry) and the correct subject
    identity. A ``ref_digest`` on a manifest ref is never verifiable here
    (no canonical manifest-payload-digest API exists at this surface) and
    always fails closed rather than being silently ignored.
  - ``required_capabilities`` (from either the task or the intent) must
    each be literally declared in the union of the resolved backend's and
    processor's ``supported_contract_versions``.
  - MUTUAL COMPATIBILITY — the one-directional gotcha this module exists
    to enforce: the resolved (backend, processor) pair is admissible only
    when BOTH sides declare each other (``backend.compatible_processors``
    contains the processor's name AND ``processor.compatible_backends``
    contains the backend's name). This check runs UNCONDITIONALLY for
    every admission call (it is a structural fact about the two manifests
    actually being used, independent of what any one task's allow-lists
    say) — at the locked ACES 0.23.1 surface, the published
    reference-processor manifest names only ``stub`` as a compatible
    backend while ``create_aptl_manifest()`` names
    ``aces-reference-processor`` as compatible, so this gate currently
    rejects EVERY admission that uses the real default manifests. That is
    the correct, ADR-mandated fail-closed behavior, not a bug: "Strict
    mutual apparatus-manifest compatibility cannot be fabricated by
    patching either payload locally; fail closed until the canonical ACES
    declaration and the requested task constraints are mutually
    satisfiable" (ADR-047 Gotchas). It is exercised here with real,
    unpatched ACES manifest objects — never by constructing a fake
    manifest whose ``compatible_backends``/``compatible_processors`` was
    hand-edited to make the pair line up.

  DEBUG OVERRIDE (``policy.allow_uncertified_apparatus``, default
  ``False``): an explicit product decision lets dev/test admit against the
  REAL ``aptl`` manifest despite the above one-directional mismatch.
  ``check_apparatus_admission`` returns ``tuple[Diagnostic, ...]`` of
  non-fatal warnings (empty in the normal case) rather than ``None``. When
  mutual-compat is the ONLY failing gate AND the flag is set, that one
  mismatch is downgraded to a single ``Severity.WARNING`` diagnostic
  (code ``aptl.experiment-admission.apparatus-uncertified-compatibility``)
  returned in the tuple, and admission does NOT raise for it. Every other
  gate — identity mismatch, a missing required capability, a
  ``required_manifest_refs`` pinning failure, or an intent that widens the
  task — stays fatal regardless of the flag, and if ANY of those other
  gates also fail, the mutual-compat diagnostic is raised as a normal
  fatal diagnostic alongside them (the downgrade applies only when
  mutual-compat would otherwise be the sole reason for rejection).

* :func:`plan_condition_feasibility` / :func:`require_feasible_plan` —
  planning-only scenario feasibility via ACES's reference processor
  directly. ADR-047 "Apparatus capability admission": scenario-specific
  feasibility remains with ``RuntimeManager.plan()`` for EXECUTION, but
  admission must use the equivalent planning-only ACES API instead,
  because constructing APTL's runtime target pulls in ``AptlConfig`` and a
  ``DeploymentBackend`` — a dependency-boundary violation even with a
  no-op backend. Neither function here imports or constructs either. A
  green ``plan_condition_feasibility`` call is NOT proof of certified
  mutual apparatus-manifest compatibility (``run_reference_processor``
  does not check that — see :func:`check_apparatus_admission` above);
  admission must run both checks.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from aces_backend_protocols.manifest import BackendManifest
from aces_contracts.contracts import (
    BACKEND_MANIFEST_V2_SCHEMA_VERSION,
    PROCESSOR_MANIFEST_V2_SCHEMA_VERSION,
    ExperimentApparatusConstraintModel,
    ExperimentBackendReferenceModel,
    ExperimentManifestReferenceModel,
    ExperimentProcessorReferenceModel,
    ExperimentTaskModel,
)
from aces_contracts.diagnostics import Diagnostic, Severity
from aces_processor.capabilities import ProcessorManifest
from aces_processor.manifest import create_reference_processor_manifest
from aces_processor.reference import ReferenceProcessorResult, ScenarioInput, run_reference_processor
from aces_sdl import SDLInstantiationError

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.errors import AdmissionRejection, diagnostic, normalize_aces_failure
from aptl.core.experiment.policy import AdmissionPolicy

_ADDRESS_APPARATUS = "task.apparatus_constraints"
_ADDRESS_INTENT = "apparatus_intent"
_ADDRESS_CONDITION_PARAMETERS = "condition.parameters"

_CODE_INTENT_EXPANDS_TASK = "aptl.experiment-admission.apparatus-intent-expands-task"
_CODE_IDENTITY_UNRESOLVED = "aptl.experiment-admission.apparatus-identity-unresolved"
_CODE_MANIFEST_REF_UNVERIFIABLE = "aptl.experiment-admission.apparatus-manifest-ref-unverifiable"
_CODE_MANIFEST_REF_MISMATCH = "aptl.experiment-admission.apparatus-manifest-ref-mismatch"
_CODE_CAPABILITY_UNSUPPORTED = "aptl.experiment-admission.apparatus-capability-unsupported"
_CODE_MUTUAL_INCOMPATIBLE = "aptl.experiment-admission.apparatus-mutual-incompatible"
_CODE_UNCERTIFIED_COMPATIBILITY = "aptl.experiment-admission.apparatus-uncertified-compatibility"
_CODE_CONDITION_PARAMETERS_INVALID = "aptl.experiment-admission.condition-parameters-invalid"
_CODE_PLAN_INFEASIBLE = "aptl.experiment-admission.plan-infeasible"

_ManifestRef = ExperimentProcessorReferenceModel | ExperimentBackendReferenceModel


def check_apparatus_admission(
    task: ExperimentTaskModel,
    apparatus_intent: ExperimentApparatusConstraintModel | None,
    *,
    backend_manifest: BackendManifest | None = None,
    processor_manifest: ProcessorManifest | None = None,
    policy: AdmissionPolicy,
) -> tuple[Diagnostic, ...]:
    """Admit (or reject) a task's apparatus requirements.

    Returns a (normally empty) tuple of NON-FATAL warning diagnostics on
    success. Raises :class:`~aptl.core.experiment.errors.AdmissionRejection`
    on any FATAL gap — see the module and class docstrings for the debug
    override (``policy.allow_uncertified_apparatus``) that can downgrade an
    isolated mutual-compat mismatch to a warning instead of raising.

    ``backend_manifest``/``processor_manifest`` default to APTL's real
    canonical manifests (``create_aptl_manifest()``,
    ``create_reference_processor_manifest()``); tests inject alternatives.
    """
    resolved_backend = backend_manifest if backend_manifest is not None else create_aptl_manifest()
    resolved_processor = (
        processor_manifest if processor_manifest is not None else create_reference_processor_manifest()
    )

    constraints = task.apparatus_constraints
    diagnostics: list[Diagnostic] = []

    diagnostics.extend(_narrowing_violations(constraints, apparatus_intent))

    diagnostics.extend(
        _identity_violations(
            task_refs=constraints.allowed_processor_refs,
            intent_refs=_intent_processor_refs(apparatus_intent),
            manifest_name=resolved_processor.name,
            address=f"{_ADDRESS_APPARATUS}.allowed_processor_refs",
        )
    )
    diagnostics.extend(
        _identity_violations(
            task_refs=constraints.allowed_backend_refs,
            intent_refs=_intent_backend_refs(apparatus_intent),
            manifest_name=resolved_backend.name,
            address=f"{_ADDRESS_APPARATUS}.allowed_backend_refs",
        )
    )

    diagnostics.extend(
        _manifest_ref_violations(constraints.required_manifest_refs, resolved_backend, resolved_processor)
    )
    if apparatus_intent is not None:
        diagnostics.extend(
            _manifest_ref_violations(
                apparatus_intent.required_manifest_refs, resolved_backend, resolved_processor
            )
        )

    effective_capabilities = set(constraints.required_capabilities) | set(
        apparatus_intent.required_capabilities if apparatus_intent is not None else ()
    )
    diagnostics.extend(_capability_violations(effective_capabilities, resolved_backend, resolved_processor))

    mutual_diagnostics = _mutual_compat_violations(resolved_backend, resolved_processor)

    if diagnostics:
        # Other gates already failed: mutual-compat (if any) is not the
        # SOLE reason for rejection, so it stays fatal regardless of the
        # debug override — never silently dropped from the raised set.
        raise AdmissionRejection(tuple(diagnostics) + mutual_diagnostics)

    warnings: list[Diagnostic] = []
    if mutual_diagnostics:
        if not policy.allow_uncertified_apparatus:
            raise AdmissionRejection(mutual_diagnostics)
        warnings.append(
            diagnostic(
                _CODE_UNCERTIFIED_COMPATIBILITY,
                f"{_ADDRESS_APPARATUS}.mutual_compatibility",
                "backend and processor manifests do not mutually declare each other "
                "compatible; admitted under the allow_uncertified_apparatus debug override",
                severity=Severity.WARNING,
            )
        )
    return tuple(warnings)


def _intent_processor_refs(
    apparatus_intent: ExperimentApparatusConstraintModel | None,
) -> Sequence[ExperimentProcessorReferenceModel]:
    """Return the intent's allowed processor refs, or empty when there is no intent."""
    return apparatus_intent.allowed_processor_refs if apparatus_intent is not None else ()


def _intent_backend_refs(
    apparatus_intent: ExperimentApparatusConstraintModel | None,
) -> Sequence[ExperimentBackendReferenceModel]:
    """Return the intent's allowed backend refs, or empty when there is no intent."""
    return apparatus_intent.allowed_backend_refs if apparatus_intent is not None else ()


def _ref_key(ref: _ManifestRef) -> tuple[str, str | None]:
    """Return the (ref_id, ref_version) identity key used to compare manifest refs."""
    return (ref.ref_id, ref.ref_version)


def _narrowing_violations(
    constraints: ExperimentApparatusConstraintModel,
    apparatus_intent: ExperimentApparatusConstraintModel | None,
) -> tuple[Diagnostic, ...]:
    """``apparatus_intent`` may only narrow ``constraints``, never expand it.

    A field is only checked when BOTH sides declare it: an empty task-side
    list means the task did not restrict that axis (nothing to narrow),
    and an empty intent-side list means the intent did not touch that
    axis (nothing to check).
    """
    if apparatus_intent is None:
        return ()

    violations: list[Diagnostic] = []
    violations.extend(
        _ref_narrowing_violations(
            constraints.allowed_processor_refs,
            apparatus_intent.allowed_processor_refs,
            f"{_ADDRESS_INTENT}.allowed_processor_refs",
        )
    )
    violations.extend(
        _ref_narrowing_violations(
            constraints.allowed_backend_refs,
            apparatus_intent.allowed_backend_refs,
            f"{_ADDRESS_INTENT}.allowed_backend_refs",
        )
    )
    if constraints.required_capabilities and apparatus_intent.required_capabilities:
        allowed_capabilities = set(constraints.required_capabilities)
        for capability in apparatus_intent.required_capabilities:
            if capability not in allowed_capabilities:
                violations.append(
                    diagnostic(
                        _CODE_INTENT_EXPANDS_TASK,
                        f"{_ADDRESS_INTENT}.required_capabilities",
                        "apparatus_intent requires a capability the task's "
                        "apparatus_constraints does not require",
                    )
                )
    return tuple(violations)


def _ref_narrowing_violations(
    task_refs: Sequence[_ManifestRef], intent_refs: Sequence[_ManifestRef], address: str
) -> tuple[Diagnostic, ...]:
    """Return one violation per intent ref whose identity is absent from task_refs.

    Empty when either side is empty (nothing declared to narrow, or nothing
    declared to check).
    """
    if not task_refs or not intent_refs:
        return ()
    allowed_keys = {_ref_key(ref) for ref in task_refs}
    return tuple(
        diagnostic(
            _CODE_INTENT_EXPANDS_TASK,
            address,
            "apparatus_intent names an identity the task's apparatus_constraints does not allow",
        )
        for ref in intent_refs
        if _ref_key(ref) not in allowed_keys
    )


def _identity_violations(
    *,
    task_refs: Sequence[_ManifestRef],
    intent_refs: Sequence[_ManifestRef],
    manifest_name: str,
    address: str,
) -> tuple[Diagnostic, ...]:
    """The resolved manifest identity must appear in the effective allow-list.

    An empty ``task_refs`` means the task does not restrict this axis —
    there is nothing to resolve against. Otherwise the EFFECTIVE allow-list
    is the (already-narrowing-validated) intent list when the intent
    supplies one, else the task's own list.
    """
    violations: list[Diagnostic] = []
    if task_refs:
        effective_refs = intent_refs if intent_refs else task_refs
        names = {ref.ref_id for ref in effective_refs}
        if manifest_name not in names:
            violations.append(
                diagnostic(
                    _CODE_IDENTITY_UNRESOLVED,
                    address,
                    "the resolved manifest identity is not present in the admitted allow-list",
                )
            )
    return tuple(violations)


def _manifest_ref_violations(
    manifest_refs: Sequence[ExperimentManifestReferenceModel],
    backend_manifest: BackendManifest,
    processor_manifest: ProcessorManifest,
) -> tuple[Diagnostic, ...]:
    """Return one violation per required_manifest_refs entry that is unverifiable, mispinned, or misidentified."""
    violations: list[Diagnostic] = []
    for ref in manifest_refs:
        subject = ref.subject_ref
        if subject is None or subject.ref_kind not in ("processor", "backend"):
            continue
        address = f"{_ADDRESS_APPARATUS}.required_manifest_refs.{ref.ref_id}"

        if ref.ref_digest is not None or subject.ref_digest is not None:
            violations.append(
                diagnostic(
                    _CODE_MANIFEST_REF_UNVERIFIABLE,
                    address,
                    "admission cannot verify a manifest ref_digest against a canonical digest source",
                )
            )
            continue

        expected_literal = (
            PROCESSOR_MANIFEST_V2_SCHEMA_VERSION
            if subject.ref_kind == "processor"
            else BACKEND_MANIFEST_V2_SCHEMA_VERSION
        )
        if ref.ref_version != expected_literal:
            violations.append(
                diagnostic(
                    _CODE_MANIFEST_REF_MISMATCH,
                    address,
                    "required_manifest_refs entry does not pin the canonical manifest schema-version literal",
                )
            )
            continue

        canonical_name = processor_manifest.name if subject.ref_kind == "processor" else backend_manifest.name
        if subject.ref_id != canonical_name:
            violations.append(
                diagnostic(
                    _CODE_MANIFEST_REF_MISMATCH,
                    address,
                    "required_manifest_refs subject_ref identity does not match the canonical manifest",
                )
            )
    return tuple(violations)


def _capability_violations(
    required_capabilities: Iterable[str],
    backend_manifest: BackendManifest,
    processor_manifest: ProcessorManifest,
) -> tuple[Diagnostic, ...]:
    """Return one violation per required capability not declared by either manifest's supported_contract_versions."""
    declared = set(backend_manifest.supported_contract_versions) | set(
        processor_manifest.supported_contract_versions
    )
    missing = sorted(capability for capability in required_capabilities if capability not in declared)
    return tuple(
        diagnostic(
            _CODE_CAPABILITY_UNSUPPORTED,
            f"{_ADDRESS_APPARATUS}.required_capabilities.{capability}",
            "required capability is not declared by the canonical backend/processor manifests",
        )
        for capability in missing
    )


def _mutual_compat_violations(
    backend_manifest: BackendManifest, processor_manifest: ProcessorManifest
) -> tuple[Diagnostic, ...]:
    """Return the mutual-incompatibility violation when backend/processor don't both declare each other, else empty."""
    backend_declares_processor = processor_manifest.name in backend_manifest.compatible_processors
    processor_declares_backend = backend_manifest.name in processor_manifest.compatible_backends
    violations: list[Diagnostic] = []
    if not (backend_declares_processor and processor_declares_backend):
        violations.append(
            diagnostic(
                _CODE_MUTUAL_INCOMPATIBLE,
                f"{_ADDRESS_APPARATUS}.mutual_compatibility",
                "backend and processor manifests do not mutually declare each other compatible",
            )
        )
    return tuple(violations)


def plan_condition_feasibility(
    scenario: ScenarioInput,
    parameters: Mapping[str, object],
    *,
    backend_manifest: BackendManifest | None = None,
    profile: str | None = None,
) -> ReferenceProcessorResult:
    """Planning-only feasibility for one condition's parameter binding.

    Calls ACES's reference processor directly — no ``AptlConfig``,
    ``DeploymentBackend``, or Docker probe. ``SDLInstantiationError``
    (which ``run_reference_processor`` raises, not returns as a diagnostic,
    for a structurally broken parameter binding — a missing, unused, or
    undeclared target) is normalized into the same fail-closed
    :class:`~aptl.core.experiment.errors.AdmissionRejection` surface as
    every other admission rejection.
    """
    manifest = backend_manifest if backend_manifest is not None else create_aptl_manifest()
    try:
        return run_reference_processor(scenario, manifest, parameters=parameters, profile=profile)
    except SDLInstantiationError as exc:
        raise AdmissionRejection(
            normalize_aces_failure(
                exc, address=_ADDRESS_CONDITION_PARAMETERS, code=_CODE_CONDITION_PARAMETERS_INVALID
            )
        ) from exc


def require_feasible_plan(result: ReferenceProcessorResult, *, address: str) -> None:
    """Raise when ``result`` carries any error-severity diagnostic.

    NOTE: a valid ``result`` here is NOT proof of certified mutual
    apparatus-manifest compatibility — ``run_reference_processor`` does not
    check that (see :func:`check_apparatus_admission`).
    """
    if not result.is_valid:
        raise AdmissionRejection(
            normalize_aces_failure(result.diagnostics, address=address, code=_CODE_PLAN_INFEASIBLE)
        )
