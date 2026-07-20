"""The versioned, code-owned collector registry (ADR-047 "Apparatus and
capture capability admission"; EXP-010 / issue #752 preflight
``docs/architecture/exp-010-capture-admission-evidence-preflight.md``).

This module evolves EXP-002's ``CaptureCapability`` /
``SUPPORTED_CAPTURE_CAPABILITIES`` table (formerly in
:mod:`aptl.core.experiment.capture_mapping`) into ONE versioned registry that
is the **single source of truth** for capture support. Everything downstream
projects from it:

* admission matches an authored ``ExperimentCaptureRequirementModel`` against
  the registry and returns an immutable :class:`CaptureBinding` (never the old
  free-text owner string) — deterministic across every requirement axis and
  contract version, fail-closed on any unknown;
* the backend ``ObservationCapabilities`` manifest is an **aggregate
  projection** of the same declarations (:meth:`CollectorRegistry.
  observation_projection`), never a second hand-maintained capability matrix;
* the acquisition coordinator (EXP-010 PR 2) consumes the pinned binding to
  drive a narrow collector without re-matching a changed registry.

FAIL-CLOSED / HONESTY BASELINE. :data:`DEFAULT_COLLECTOR_REGISTRY` is EMPTY:
there is no honest end-to-end backed capture capability yet, so the production
manifest keeps ``observation=None`` (exactly as EXP-002 shipped). A capability
is added ONLY together with its collector adapter, conformance fixture, and a
turned-on manifest observation (EXP-010 PR 2) — adding a registration without
the acquisition path is the failure mode this registry exists to prevent.

A ``registration_id`` is a stable, NON-EXECUTABLE identifier
(:func:`validate_registration_id`): never an import path, class name, command,
URL, host path, credential/environment selector, or arbitrary configuration
key. Admission never resolves it to code (ADR-047 "no input controls imports,
commands, collectors, backend methods, environment names, or filesystem
roots").
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

from aces_backend_protocols.capabilities import ObservationCapabilities
from aces_contracts.contracts import ExperimentCaptureRequirementModel, ExperimentCaptureSpecModel

from aptl.core.experiment.trial_plan import compute_source_set_digest

#: Versioned identity of the registry declaration shape itself. A change to
#: the fields a registration declares, or to how the observation projection or
#: binding is computed, bumps this so a persisted plan records which registry
#: shape admitted it.
REGISTRY_SCHEMA_VERSION = "aptl-collector-registry/v1"

#: Fixed ``ObservationCapabilities.name`` for APTL's aggregate declaration.
_OBSERVATION_NAME = "aptl-observation"

#: The ACES evidence/run contract set a declared observation capability emits.
#: ``observation_capability_contract_gaps`` additionally requires these be
#: present in the manifest's top-level ``supported_contract_versions`` — the
#: manifest builder adds them whenever the projection is non-None.
OBSERVATION_EVIDENCE_CONTRACTS: frozenset[str] = frozenset(
    {
        "experiment-capture-spec-v1",
        "experiment-evidence-record-v1",
        "experiment-derived-measure-v1",
        "experiment-run-v1",
    }
)

#: A ``registration_id`` is a lowercase dotted/hyphenated slug: it starts with
#: a letter and joins alphanumeric segments with single ``.`` or ``-``. That
#: deliberately rejects uppercase (class names), ``/`` and ``\`` (paths),
#: ``://`` (URLs), ``:`` (schemes/host:port), ``..`` (traversal), whitespace,
#: and every shell/argv metacharacter — so a registration ID can never be
#: mistaken for something admission could execute or resolve.
_REGISTRATION_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")

#: Upper bound on a registration ID's length (defense against absurd inputs in
#: a future dynamically-built registry; the built-ins are far shorter).
_MAX_REGISTRATION_ID_LEN = 128


class CaptureVisibility(str, Enum):
    """Controlled visibility class of a collector's evidence (preflight
    "Visibility boundary").

    Capture authorization is a SEPARATE projection from participant
    visibility: an ``EVALUATOR_ONLY`` or ``APPARATUS_ONLY`` collector may be
    authorized to retain evidence that must never enter a participant
    response. The binding carries this class so the acquisition coordinator
    (EXP-010 PR 2) can project it server-side.
    """

    PARTICIPANT_VISIBLE = "participant-visible"
    DISCLOSED = "disclosed"
    EVALUATOR_ONLY = "evaluator-only"
    APPARATUS_ONLY = "apparatus-only"


class RegistrationIdError(ValueError):
    """Raised when a ``registration_id`` is not a safe non-executable slug."""


def validate_registration_id(value: str) -> str:
    """Return ``value`` if it is a safe, non-executable registration ID; else raise.

    The rule is intentionally strict (see :data:`_REGISTRATION_ID_RE`): the ID
    identifies a trusted built-in registration and must never be resolvable to
    an import path, class, command, URL, host path, or config key.
    """
    if not isinstance(value, str) or not value:
        raise RegistrationIdError("registration_id must be a non-empty string")
    if len(value) > _MAX_REGISTRATION_ID_LEN:
        raise RegistrationIdError("registration_id exceeds the maximum length")
    if _REGISTRATION_ID_RE.fullmatch(value) is None:
        raise RegistrationIdError("registration_id is not a safe non-executable slug")
    return value


@dataclass(frozen=True)
class CaptureLimits:
    """Immutable size/count/time bounds a collector is admitted under.

    The coordinator (EXP-010 PR 2) enforces these while streaming — a
    collector never buffers unbounded or exceeds its admitted budget.
    """

    max_bytes: int
    max_artifact_count: int
    max_duration_s: int


@dataclass(frozen=True)
class CollectorRegistration:
    """One trusted, code-owned collector's static capability declaration.

    This is the whole capability surface admission and the observation
    projection read (preflight "One declaration, one admitted binding"): the
    supported ACES capture-spec contract version, the observation channel kind
    (a governed ``observation-channel-kinds`` term), capture kind/scope, window
    semantics, media types, required artifact roles, sensitivities,
    redaction/integrity/sealing/chain-of-custody/retention support, loss
    disclosure, visibility class, and limits. It carries NO factory, import
    path, or executable reference — the trusted adapter wiring is composed
    separately (EXP-010 PR 2).

    ``channel_kind``, ``capture_kind``, and ``sealing_modes`` MUST be governed
    controlled-vocabulary terms (``observation-channel-kinds`` /
    ``observation-capture-kinds`` / ``observation-sealing-modes``); the
    observation projection validates them against ACES's catalog, so a
    registration with an ungoverned term fails when the manifest is built.
    """

    registration_id: str
    implementation_version: str
    contract_version: str
    channel_kind: str
    capture_kind: str
    capture_scope: str
    window_kinds: frozenset[str]
    media_types: frozenset[str]
    required_artifact_roles: frozenset[str]
    supported_sensitivities: frozenset[str]
    supports_redaction: bool
    integrity_modes: frozenset[str]
    sealing_modes: frozenset[str]
    supports_chain_of_custody: bool
    supports_retention: bool
    supports_loss_disclosure: bool
    visibility_class: CaptureVisibility
    limits: CaptureLimits

    def __post_init__(self) -> None:
        """Validate the registration ID is a safe non-executable slug at construction."""
        validate_registration_id(self.registration_id)

    def declaration_projection(self) -> dict[str, object]:
        """Return the canonical-JSON-ready projection of this registration's declaration.

        Sets are emitted as sorted lists so the RFC 8785 digest is
        order-independent; this projection is what
        :attr:`CaptureBinding.effective_config_digest` pins.
        """
        return {
            "registry_schema": REGISTRY_SCHEMA_VERSION,
            "registration_id": self.registration_id,
            "implementation_version": self.implementation_version,
            "contract_version": self.contract_version,
            "channel_kind": self.channel_kind,
            "capture_kind": self.capture_kind,
            "capture_scope": self.capture_scope,
            "window_kinds": sorted(self.window_kinds),
            "media_types": sorted(self.media_types),
            "required_artifact_roles": sorted(self.required_artifact_roles),
            "supported_sensitivities": sorted(self.supported_sensitivities),
            "supports_redaction": self.supports_redaction,
            "integrity_modes": sorted(self.integrity_modes),
            "sealing_modes": sorted(self.sealing_modes),
            "supports_chain_of_custody": self.supports_chain_of_custody,
            "supports_retention": self.supports_retention,
            "supports_loss_disclosure": self.supports_loss_disclosure,
            "visibility_class": self.visibility_class.value,
            "max_bytes": self.limits.max_bytes,
            "max_artifact_count": self.limits.max_artifact_count,
            "max_duration_s": self.limits.max_duration_s,
        }

    def effective_config_digest(self) -> str:
        """Return ``sha256:<hex>`` of this registration's canonical declaration.

        Pins the exact capability version a plan admitted, so runtime can
        verify the registration has not silently changed (preflight: "Runtime
        verifies the pinned registration and digest and never re-matches").
        """
        return compute_source_set_digest(self.declaration_projection())


@dataclass(frozen=True)
class CaptureBinding:
    """The immutable result of admitting one capture requirement.

    Everything runtime needs to acquire the evidence without re-matching a
    (possibly changed) registry is pinned here and, via
    :meth:`binding_projection`, folded into the canonical trial-plan bytes
    before any range mutation. ``channel_ref_*`` records the AUTHOR's
    measurement channel the evidence satisfies; ``registration_id`` /
    ``channel_kind`` record which trusted APTL collector produces it.
    ``accepted_limitation`` / ``comparability_disclosure_ref`` are ``None``
    unless a trusted policy explicitly accepted a supported degradation (never
    inferred).
    """

    capture_spec_id: str
    requirement_id: str
    window_refs: tuple[str, ...]
    registration_id: str
    implementation_version: str
    contract_version: str
    effective_config_digest: str
    channel_ref_id: str
    channel_ref_version: str | None
    channel_kind: str
    capture_kind: str
    capture_scope: str
    expected_media_types: tuple[str, ...]
    required_artifact_roles: tuple[str, ...]
    sensitivity: str
    redaction_required: bool
    integrity_requirements: tuple[str, ...]
    retention_policy: str | None
    loss_disclosure_required: bool
    visibility_class: CaptureVisibility
    limits: CaptureLimits
    accepted_limitation: str | None = None
    comparability_disclosure_ref: str | None = None

    def binding_projection(self) -> dict[str, object]:
        """Return the canonical-JSON-ready projection pinned into the trial plan.

        The requirement's set-valued axes (``window_refs``,
        ``expected_media_types``, ``required_artifact_roles``,
        ``integrity_requirements``) are semantically unordered, so they are
        SORTED here — ADR-047 "sort semantically unordered maps/sets": two
        requirements identical up to authored list order must yield the same
        plan digest, so incidental ACES-document ordering never leaks into
        identity. The projection excludes nothing identity-bearing, so the plan
        digest changes iff a binding meaningfully changes.
        """
        return {
            "capture_spec_id": self.capture_spec_id,
            "requirement_id": self.requirement_id,
            "window_refs": sorted(self.window_refs),
            "registration_id": self.registration_id,
            "implementation_version": self.implementation_version,
            "contract_version": self.contract_version,
            "effective_config_digest": self.effective_config_digest,
            "channel_ref_id": self.channel_ref_id,
            "channel_ref_version": self.channel_ref_version,
            "channel_kind": self.channel_kind,
            "capture_kind": self.capture_kind,
            "capture_scope": self.capture_scope,
            "expected_media_types": sorted(self.expected_media_types),
            "required_artifact_roles": sorted(self.required_artifact_roles),
            "sensitivity": self.sensitivity,
            "redaction_required": self.redaction_required,
            "integrity_requirements": sorted(self.integrity_requirements),
            "retention_policy": self.retention_policy,
            "loss_disclosure_required": self.loss_disclosure_required,
            "visibility_class": self.visibility_class.value,
            "max_bytes": self.limits.max_bytes,
            "max_artifact_count": self.limits.max_artifact_count,
            "max_duration_s": self.limits.max_duration_s,
            "accepted_limitation": self.accepted_limitation,
            "comparability_disclosure_ref": self.comparability_disclosure_ref,
        }


def _window_kinds_by_ref(spec: ExperimentCaptureSpecModel) -> Mapping[str, str]:
    """Return a map from each capture-window ID to its window kind for spec."""
    return {window.window_id: window.window_kind for window in spec.capture_windows}


def _windows_supported(
    window_refs: Sequence[str],
    window_kinds_by_ref: Mapping[str, str],
    supported_window_kinds: frozenset[str],
) -> bool:
    """Return whether every referenced window resolves to a supported window kind.

    A window ref that does not resolve to a declared spec window is treated as
    unsupported (fail closed) rather than skipped.
    """
    for window_ref in window_refs:
        kind = window_kinds_by_ref.get(window_ref)
        if kind is None or kind not in supported_window_kinds:
            return False
    return True


def _registration_covers(
    registration: CollectorRegistration,
    requirement: ExperimentCaptureRequirementModel,
    *,
    contract_version: str,
    window_kinds_by_ref: Mapping[str, str],
) -> bool:
    """Return whether registration deterministically covers requirement on every axis.

    Every authored requirement axis is checked (preflight "Registry/policy
    validation"): contract version, capture kind/scope, window semantics, media
    types, artifact roles, sensitivity, integrity, redaction, retention, and
    loss disclosure. Subset axes require the requirement to be a SUBSET of what
    the registration declares — a requirement asking for more than a
    registration covers is not matched by it. The author's ``channel_ref`` is
    NOT a match axis: it names an author-defined measurement channel APTL
    cannot pre-enumerate; it is recorded on the binding for traceability
    instead. Collected as one boolean list so this stays a single return.
    """
    checks = (
        registration.contract_version == contract_version,
        registration.capture_kind == requirement.capture_kind,
        registration.capture_scope == requirement.capture_scope,
        _windows_supported(requirement.window_refs, window_kinds_by_ref, registration.window_kinds),
        frozenset(requirement.expected_media_types) <= registration.media_types,
        frozenset(requirement.required_artifact_roles) <= registration.required_artifact_roles,
        requirement.sensitivity in registration.supported_sensitivities,
        frozenset(requirement.integrity_requirements) <= registration.integrity_modes,
        registration.supports_redaction or requirement.redaction_policy is None,
        registration.supports_retention or requirement.retention_policy is None,
        registration.supports_loss_disclosure or not requirement.loss_disclosure_required,
    )
    return all(checks)


@dataclass(frozen=True)
class CollectorRegistry:
    """An immutable set of trusted collector registrations, keyed by ID.

    Construction rejects duplicate registration IDs. The registry is the sole
    detailed source of truth: :meth:`match` binds a requirement and
    :meth:`observation_projection` aggregates the same declarations into the
    backend manifest's observation capability.
    """

    registrations: tuple[CollectorRegistration, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicate registration IDs at construction."""
        ids = [registration.registration_id for registration in self.registrations]
        if len(set(ids)) != len(ids):
            raise ValueError("CollectorRegistry contains duplicate registration IDs")

    def _ordered(self) -> tuple[CollectorRegistration, ...]:
        """Return registrations in a deterministic (ID-sorted) order for selection."""
        return tuple(sorted(self.registrations, key=lambda registration: registration.registration_id))

    def match(
        self,
        spec: ExperimentCaptureSpecModel,
        requirement: ExperimentCaptureRequirementModel,
    ) -> CaptureBinding | None:
        """Return the immutable binding for requirement, or ``None`` if unsupported.

        Selection is deterministic: registrations are scanned in ID-sorted
        order and the first that covers every axis is bound, so registration
        insertion order never affects the result. ``None`` (fail closed) means
        no trusted registration covers the requirement — the caller rejects
        admission; it is never a silent skip.
        """
        window_kinds_by_ref = _window_kinds_by_ref(spec)
        for registration in self._ordered():
            if _registration_covers(
                registration,
                requirement,
                contract_version=spec.schema_version,
                window_kinds_by_ref=window_kinds_by_ref,
            ):
                return _bind(spec, requirement, registration)
        return None

    def observation_projection(self) -> ObservationCapabilities | None:
        """Return the aggregate ``ObservationCapabilities``, or ``None`` when empty.

        ``None`` for an empty registry keeps the manifest honestly declaring no
        observation capability (``create_aptl_manifest().observation is None``)
        until a real capability is genuinely backed. Otherwise every scalar
        support flag is the OR across registrations and every vocabulary set is
        their union; ``supported_evidence_contracts`` is the fixed
        :data:`OBSERVATION_EVIDENCE_CONTRACTS` the observation emits.
        """
        if not self.registrations:
            return None
        return ObservationCapabilities(
            name=_OBSERVATION_NAME,
            supported_capture_kinds=frozenset(r.capture_kind for r in self.registrations),
            supported_channel_kinds=frozenset(r.channel_kind for r in self.registrations),
            supported_evidence_contracts=OBSERVATION_EVIDENCE_CONTRACTS,
            supported_media_types=frozenset().union(*(r.media_types for r in self.registrations)),
            supported_sealing_modes=frozenset().union(*(r.sealing_modes for r in self.registrations)),
            supports_redaction=any(r.supports_redaction for r in self.registrations),
            supports_loss_disclosure=any(r.supports_loss_disclosure for r in self.registrations),
            supports_chain_of_custody=any(r.supports_chain_of_custody for r in self.registrations),
        )


def _bind(
    spec: ExperimentCaptureSpecModel,
    requirement: ExperimentCaptureRequirementModel,
    registration: CollectorRegistration,
) -> CaptureBinding:
    """Build the immutable :class:`CaptureBinding` for a covered requirement."""
    return CaptureBinding(
        capture_spec_id=spec.capture_spec_id,
        requirement_id=requirement.requirement_id,
        window_refs=tuple(requirement.window_refs),
        registration_id=registration.registration_id,
        implementation_version=registration.implementation_version,
        contract_version=registration.contract_version,
        effective_config_digest=registration.effective_config_digest(),
        channel_ref_id=requirement.channel_ref.ref_id,
        channel_ref_version=requirement.channel_ref.ref_version,
        channel_kind=registration.channel_kind,
        capture_kind=requirement.capture_kind,
        capture_scope=requirement.capture_scope,
        expected_media_types=tuple(requirement.expected_media_types),
        required_artifact_roles=tuple(requirement.required_artifact_roles),
        sensitivity=requirement.sensitivity,
        redaction_required=requirement.redaction_policy is not None,
        integrity_requirements=tuple(requirement.integrity_requirements),
        retention_policy=requirement.retention_policy,
        loss_disclosure_required=requirement.loss_disclosure_required,
        visibility_class=registration.visibility_class,
        limits=registration.limits,
    )


#: The production registry. EMPTY by design (see the module docstring): no
#: capture capability is honestly backed end-to-end yet, so the manifest keeps
#: ``observation=None`` and every capture requirement fails closed. EXP-010
#: PR 2 populates real registrations together with their acquisition adapters,
#: conformance fixtures, and a turned-on observation projection.
DEFAULT_COLLECTOR_REGISTRY = CollectorRegistry()
