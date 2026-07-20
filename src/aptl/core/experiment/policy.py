"""Experiment-admission resource limits and allocation-ordering policy.

ADR-047 "Deterministic immutable trial plan": ``allocation_method``,
stochastic-control ``role``, and ordering behavior are executable only when
they map to a supported, versioned controller policy — free-form text is
never evaluated or silently approximated. This module owns that mapping
plus the in-code resource limits admission enforces before any expensive
parsing or trial expansion.

These are in-code defaults, not :class:`~aptl.core.config.AptlConfig`
fields: ADR-047 "Config shape" reserves durable ``AptlConfig`` settings for
non-secret admission limits with a *real* consumer, and trial-plan
expansion (a later stage) is that consumer's home, not this one.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from aptl.core.experiment.errors import AdmissionRejection, diagnostic

#: Stable identity for the resource-limit/mapping policy itself. A future
#: policy revision (e.g. a new supported allocation method) bumps this
#: string so a persisted plan can record exactly which policy admitted it.
_POLICY_VERSION = "aptl-admission/v1"


@dataclass(frozen=True)
class CaptureLimitationAcceptance:
    """A trusted operator's explicit acceptance of one supported capture degradation.

    ADR-047 / EXP-010 preflight ("One declaration, one admitted binding"): ACES
    capture-spec v1 has no general ``required`` flag, so authored capture
    requirements are **required by default**. A degradation is admitted ONLY
    when the policy carries an explicit acceptance here — a stable
    ``limitation_code`` plus the ``comparability_disclosure_ref`` that discloses
    its effect on comparability — and that acceptance is persisted into the
    plan binding. Optionality is NEVER inferred from notes, validity text, an
    empty collector result, or historical best-effort behavior.
    """

    limitation_code: str
    comparability_disclosure_ref: str


class OrderingKind(str, Enum):
    """A supported, versioned trial-ordering behavior.

    Trial-plan expansion (a later stage) imports this enum rather than
    branching on the raw ``allocation_method`` string — ADR-047 forbids
    letting condition names or free-text method values select behavior in
    ``if``/``match`` branches.
    """

    #: Ordinal ``0..target_run_count-1`` (flat allocation, no conditions).
    FLAT = "flat"
    #: The authored ``compared_conditions`` order, then a zero-based
    #: replication ordinal within each condition.
    CONDITION_MAJOR_REPLICATION = "condition-major-replication"


#: Controlled mapping from the ACES contract's free-text
#: ``allocation_method`` to a supported :class:`OrderingKind`. Additive
#: only: a future supported method is a new entry here (plus conformance
#: tests), never a scenario/condition-name branch.
_DEFAULT_SUPPORTED_ALLOCATION_METHODS: MappingProxyType[str, OrderingKind] = MappingProxyType(
    {
        "balanced": OrderingKind.CONDITION_MAJOR_REPLICATION,
        "condition-major": OrderingKind.CONDITION_MAJOR_REPLICATION,
        "flat": OrderingKind.FLAT,
    }
)

#: Subset of ``ExperimentStochasticControlModel.role``'s six ACES-legal
#: literal values that the controller can currently derive a deterministic,
#: domain-separated seed/order from (ADR-047: "A seed or randomized order
#: is derived with a documented, domain-separated cryptographic hash").
#: The remaining ACES-legal roles are structurally valid but not yet an
#: admittable controller policy, so they fail closed here.
_DEFAULT_SUPPORTED_STOCHASTIC_CONTROL_ROLES: frozenset[str] = frozenset({"seed", "randomization"})

_DEFAULT_SUPPORTED_ORDERINGS: frozenset[OrderingKind] = frozenset(
    {OrderingKind.FLAT, OrderingKind.CONDITION_MAJOR_REPLICATION}
)


@dataclass(frozen=True)
class AdmissionPolicy:
    """In-code experiment-admission resource limits and supported mappings.

    All byte/count limits are enforced BEFORE expensive parsing or trial
    expansion (ADR-047 "Authorized artifact resolution"). ``policy_version``
    is recorded alongside an admitted plan so a later replay can tell
    whether the same policy produced it.
    """

    policy_version: str = _POLICY_VERSION

    #: Byte bound for the root experiment-authoring-input document, applied
    #: before ``parse_experiment_spec`` ever sees the bytes.
    max_root_bytes: int = 1 * 1024 * 1024
    #: Byte bound for any single resolved artifact (task, capture-spec,
    #: scenario, associated artifact).
    max_artifact_bytes: int = 16 * 1024 * 1024
    #: Byte bound across every artifact resolved during one admission.
    max_aggregate_bytes: int = 128 * 1024 * 1024
    #: Maximum distinct artifact references resolved during one admission.
    max_reference_count: int = 256
    #: Maximum total planned trials across the whole allocation.
    max_allocation_size: int = 10_000
    #: Maximum structural nesting depth admission will walk (same order of
    #: magnitude as ``aces_sdl.SDLParserLimits.max_depth``).
    max_nesting_depth: int = 128

    #: DEBUG-ONLY escape hatch, default ``False`` (production stays
    #: strict/fail-closed). At the locked ACES 0.23.1 surface, the published
    #: reference-processor manifest names only ``stub`` as a compatible
    #: backend, so ``check_apparatus_admission`` rejects EVERY admission
    #: that uses the real default manifests (ADR-047 Gotchas). This is an
    #: explicit product decision to let dev/test admit against the REAL
    #: ``aptl`` manifest anyway: when mutual apparatus-manifest
    #: compatibility is the ONLY failing admission gate,
    #: ``check_apparatus_admission`` downgrades that one mismatch to a
    #: non-fatal warning instead of raising. Every OTHER gate (identity
    #: mismatch, missing required capability, a ``required_manifest_refs``
    #: pinning failure, an intent that widens the task) stays fatal
    #: regardless of this flag — it narrows exactly one documented,
    #: structural gap, never the whole admission surface.
    allow_uncertified_apparatus: bool = False

    #: Explicit per-requirement capture-degradation acceptances, keyed by the
    #: fully-qualified ``"{capture_spec_id}.{requirement_id}"`` (EXP-010
    #: preflight). Empty by default: with no entry, every authored capture
    #: requirement is required and an unbound requirement fails closed. An
    #: entry annotates its bound requirement's plan binding with the accepted
    #: limitation + comparability disclosure so the degradation is auditable,
    #: never silent.
    accepted_capture_limitations: Mapping[str, CaptureLimitationAcceptance] = field(
        default_factory=lambda: MappingProxyType({})
    )

    supported_allocation_methods: MappingProxyType[str, OrderingKind] = field(
        default_factory=lambda: _DEFAULT_SUPPORTED_ALLOCATION_METHODS
    )
    supported_stochastic_control_roles: frozenset[str] = field(
        default_factory=lambda: _DEFAULT_SUPPORTED_STOCHASTIC_CONTROL_ROLES
    )
    supported_orderings: frozenset[OrderingKind] = field(
        default_factory=lambda: _DEFAULT_SUPPORTED_ORDERINGS
    )


def default_admission_policy() -> AdmissionPolicy:
    """Return the standard :class:`AdmissionPolicy` (in-code defaults)."""
    return AdmissionPolicy()


def resolve_allocation_ordering(policy: AdmissionPolicy, allocation_method: str) -> OrderingKind:
    """Map a free-text ``allocation_method`` to a supported ordering.

    ``allocation_method`` is untrusted, authored free text
    (``ExperimentRunAllocationPlanModel.allocation_method: NonEmptyString``)
    — it is looked up in ``policy.supported_allocation_methods`` and never
    evaluated, formatted into a shell/import/template, or fuzzily matched.
    An unmapped value raises :class:`AdmissionRejection`; the raw value is
    deliberately never echoed into the diagnostic message.
    """
    kind = policy.supported_allocation_methods.get(allocation_method)
    if kind is None:
        raise AdmissionRejection(
            (
                diagnostic(
                    "aptl.experiment-admission.allocation-method-unsupported",
                    "run_plan.allocation.allocation_method",
                    "allocation_method does not map to a supported ordering policy",
                ),
            )
        )
    return kind
