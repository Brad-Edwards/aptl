"""Deterministic immutable trial-plan expansion (ADR-047 "Deterministic
immutable trial plan").

Pure, side-effect-free expansion from an admitted
``ExperimentSpecModel.run_plan`` (flat ``target_run_count`` XOR condition
``allocation``) into an immutable, host-independent :class:`TrialPlan` of
:class:`PlannedTrial` value objects. No I/O and no persistence — this
module only builds in-memory, hashable plan data; a later stage wires the
result through ``LocalRunStore.create_json_once``.

The trial plan is an APTL-internal execution journal, not a portable ACES
experiment/task/study/run/apparatus/capture/analysis contract (ADR-047). It
carries only source identities/digests, canonical condition/factor
assignments, resolved non-secret parameter bindings, stochastic controls,
ordering coordinates, and stable planned-trial IDs.

Determinism is the whole point: two expansions of the same admitted spec —
on any host, in any process, regardless of ``PYTHONHASHSEED``, and
regardless of the key-insertion order of any authored dict
(``condition_assignments``, ``factor_levels``) — must produce
byte-identical :attr:`TrialPlan.canonical_bytes`. That rules out Python
``hash()``, ``set``/``dict`` iteration order leaking into anything but a
sorted or RFC 8785 canonical-JSON projection, wall-clock time, UUIDs, and
ambient/library RNG (ADR-047 "Deterministic immutable trial plan" /
"Gotchas"). Every planned-trial ID and derived seed is a SHA-256 digest of
a fixed, versioned domain-separation prefix plus the caller-supplied
``source_set_digest`` and that trial's logical coordinates (condition ID —
or a flat sentinel — and replication ordinal, plus, for seeds, the
stochastic control ID).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

import rfc8785
from aces_contracts.experiment_spec import ExperimentSpecModel

from aptl.core.experiment.errors import AdmissionRejection, diagnostic
from aptl.core.experiment.policy import AdmissionPolicy, OrderingKind, resolve_allocation_ordering

# ---------------------------------------------------------------------------
# Domain-separation constants
# ---------------------------------------------------------------------------

#: Versioned domain separator for stochastic-seed derivation. A future
#: change to the derivation formula, field order, or field encoding bumps
#: the version suffix (never reuses one) so old plan bytes can never
#: silently reinterpret under a new formula.
_SEED_DOMAIN = b"aptl.exp.trial-seed/v1"

#: Versioned domain separator for planned-trial-ID derivation. Independent
#: from ``_SEED_DOMAIN`` so a seed-only or ID-only algorithm revision never
#: collides with the other.
_TRIAL_ID_DOMAIN = b"aptl.exp.trial-id/v1"

#: ASCII unit separator (0x1F) used to join hash-input fields. Not a legal
#: character in any authored ACES identifier, so it cannot be abused to
#: fabricate a cross-field collision (e.g. by embedding the separator
#: inside a condition ID to make two distinct coordinate tuples hash the
#: same input bytes).
_FIELD_SEP = b"\x1f"

#: Sentinel substituted for ``condition_id`` in a flat allocation (there is
#: no condition). A single :class:`TrialPlan` is always structurally either
#: flat (every trial's ``condition_id`` is ``None``) or condition-based
#: (every trial's ``condition_id`` is a real authored ID), so this can
#: never collide with an authored condition ID within the same plan.
_FLAT_CONDITION_SENTINEL = "flat"

#: The subset of admitted stochastic-control roles that receive a derived
#: seed. Currently identical to
#: ``AdmissionPolicy.supported_stochastic_control_roles``'s default, but
#: kept as an independent, explicit set: a future supported role that is
#: *not* seed-bearing (e.g. a scheduling-only role) would be admitted by
#: policy without gaining a meaningless derived seed here.
_SEED_BEARING_ROLES = frozenset({"seed", "randomization"})

_PLAN_ID_PREFIX = "plan-"
_TRIAL_ID_PREFIX = "trial-"

#: Versioned identity for the canonical plan projection shape itself
#: (distinct from any ACES ``schema_version`` literal — this is an
#: APTL-internal journal format, never an ACES contract).
_PLAN_PROJECTION_SCHEMA = "aptl-experiment-trial-plan/v1"

_ADDRESS_RUN_PLAN = "run_plan"
_ADDRESS_STOCHASTIC_CONTROLS = "run_plan.stochastic_controls"
_ADDRESS_ALLOCATION_METHOD = "run_plan.allocation.allocation_method"

_CODE_ALLOCATION_TOO_LARGE = "aptl.experiment-admission.allocation-too-large"
_CODE_STOCHASTIC_ROLE_UNSUPPORTED = "aptl.experiment-admission.stochastic-control-role-unsupported"
_CODE_ALLOCATION_ORDERING_MISMATCH = "aptl.experiment-admission.allocation-ordering-mismatch"


@dataclass(frozen=True)
class PlannedTrial:
    """One immutable planned trial coordinate within a :class:`TrialPlan`.

    Every field is a scalar or an already-sorted tuple. No list or dict
    escapes to a caller, so nothing here is mutable after construction.
    """

    planned_trial_id: str
    condition_id: str | None
    replication_ordinal: int
    ordering_index: int
    factor_levels: tuple[tuple[str, str], ...]
    parameter_bindings: tuple[tuple[str, object], ...]
    stochastic_seeds: tuple[tuple[str, str], ...]
    scenario_snapshot_digest: str | None
    capture_spec_refs: tuple[str, ...]


@dataclass(frozen=True)
class TrialPlan:
    """An immutable, deterministically-derived plan for one admitted spec.

    ``canonical_bytes``/``plan_digest`` are RFC 8785 canonical JSON (and its
    SHA-256 digest) of a projection that excludes admission time and any
    host-absolute/temp path — two expansions of the same admitted inputs
    always produce byte-identical ``canonical_bytes``.
    """

    plan_id: str
    policy_version: str
    source_set_digest: str
    ordering_kind: OrderingKind
    trials: tuple[PlannedTrial, ...]
    canonical_bytes: bytes
    plan_digest: str


def compute_source_set_digest(source_set_projection: Mapping[str, object]) -> str:
    """Return ``sha256:<hex>`` of the RFC 8785 canonical bytes of ``source_set_projection``.

    The caller builds ``source_set_projection`` from resolved artifact
    identities/digests/versions and must already exclude host-absolute/temp
    paths and admission time before it reaches here — this function
    performs no filtering of its own, only canonicalization and hashing.
    """
    canonical = rfc8785.dumps(dict(source_set_projection))
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _reject(code: str, address: str, message: str) -> AdmissionRejection:
    """Build a one-diagnostic AdmissionRejection for a trial-plan expansion failure."""
    return AdmissionRejection((diagnostic(code, address, message),))


def _coordinate(condition_id: str | None) -> str:
    """Return condition_id, or the flat-allocation sentinel when there is no condition."""
    return _FLAT_CONDITION_SENTINEL if condition_id is None else condition_id


def _derive_seed(
    *, source_set_digest: str, condition_id: str | None, replication_ordinal: int, control_id: str
) -> str:
    """Derive one stochastic control's seed hex digest from the plan's source-set digest and trial coordinate."""
    digest_input = (
        _SEED_DOMAIN
        + _FIELD_SEP
        + source_set_digest.encode("utf-8")
        + _FIELD_SEP
        + _coordinate(condition_id).encode("utf-8")
        + _FIELD_SEP
        + str(replication_ordinal).encode("utf-8")
        + _FIELD_SEP
        + control_id.encode("utf-8")
    )
    return hashlib.sha256(digest_input).hexdigest()


def _derive_planned_trial_id(
    *, source_set_digest: str, condition_id: str | None, replication_ordinal: int
) -> str:
    """Derive one trial's planned_trial_id hex digest from the plan's source-set digest and trial coordinate."""
    digest_input = (
        _TRIAL_ID_DOMAIN
        + _FIELD_SEP
        + source_set_digest.encode("utf-8")
        + _FIELD_SEP
        + _coordinate(condition_id).encode("utf-8")
        + _FIELD_SEP
        + str(replication_ordinal).encode("utf-8")
    )
    return _TRIAL_ID_PREFIX + hashlib.sha256(digest_input).hexdigest()


def _validate_stochastic_controls(spec: ExperimentSpecModel, *, policy: AdmissionPolicy) -> None:
    """Reject when any stochastic control's role does not map to a supported controller policy."""
    for control in spec.run_plan.stochastic_controls:
        if control.role not in policy.supported_stochastic_control_roles:
            raise _reject(
                _CODE_STOCHASTIC_ROLE_UNSUPPORTED,
                f"{_ADDRESS_STOCHASTIC_CONTROLS}.{control.control_id}.role",
                "stochastic control role does not map to a supported controller policy",
            )


def _resolve_ordering_kind(spec: ExperimentSpecModel, *, policy: AdmissionPolicy) -> OrderingKind:
    """Resolve run_plan's ordering kind (flat vs. condition-major), failing closed on an unsupported alloc method."""
    run_plan = spec.run_plan
    has_allocation = run_plan.allocation is not None
    has_flat_count = run_plan.target_run_count is not None
    if has_allocation == has_flat_count:
        # ACES's own model validator already enforces this XOR at parse
        # time; this is a defensive invariant check on an already-admitted
        # model, not a user-triggerable failure mode.
        raise AssertionError(
            "run_plan must declare exactly one of allocation or target_run_count"
        )

    if not has_allocation:
        return OrderingKind.FLAT

    kind = resolve_allocation_ordering(policy, run_plan.allocation.allocation_method)
    if kind is not OrderingKind.CONDITION_MAJOR_REPLICATION:
        # The method resolved to a *supported* ordering, but not one this
        # expander implements for a condition allocation (currently the
        # only condition-shaped algorithm is condition-major-replication).
        # Fail closed rather than silently mis-expand.
        raise _reject(
            _CODE_ALLOCATION_ORDERING_MISMATCH,
            _ADDRESS_ALLOCATION_METHOD,
            "allocation_method resolves to an ordering incompatible with a condition allocation",
        )
    return kind


def _capture_spec_refs(spec: ExperimentSpecModel) -> tuple[str, ...]:
    """Return the capture-spec reference IDs every trial in this plan carries."""
    return tuple(ref.ref_id for ref in spec.capture_spec_refs)


def _build_seeds(
    spec: ExperimentSpecModel,
    *,
    source_set_digest: str,
    condition_id: str | None,
    replication_ordinal: int,
) -> tuple[tuple[str, str], ...]:
    """Build one trial's sorted (control_id, seed) pairs for every seed-bearing stochastic control."""
    seeds = [
        (
            control.control_id,
            _derive_seed(
                source_set_digest=source_set_digest,
                condition_id=condition_id,
                replication_ordinal=replication_ordinal,
                control_id=control.control_id,
            ),
        )
        for control in spec.run_plan.stochastic_controls
        if control.role in _SEED_BEARING_ROLES
    ]
    return tuple(sorted(seeds))


@dataclass(frozen=True)
class _TrialCoordinate:
    """One trial's ordering coordinate: its condition (``None`` for a flat
    plan), replication ordinal, and overall ordering index. Bundled so
    :func:`_build_trial` stays within the 7-parameter budget (S107)."""

    condition_id: str | None
    replication_ordinal: int
    ordering_index: int


def _build_trial(
    spec: ExperimentSpecModel,
    *,
    source_set_digest: str,
    coordinate: _TrialCoordinate,
    factor_levels: tuple[tuple[str, str], ...],
    parameter_bindings: tuple[tuple[str, object], ...],
    condition_snapshot_digests: Mapping[str, str] | None,
    capture_spec_refs: tuple[str, ...],
) -> PlannedTrial:
    """Build one immutable PlannedTrial, deriving its ID and stochastic seeds from source_set_digest and coordinate."""
    scenario_snapshot_digest = (
        condition_snapshot_digests.get(coordinate.condition_id) if condition_snapshot_digests else None
    )
    return PlannedTrial(
        planned_trial_id=_derive_planned_trial_id(
            source_set_digest=source_set_digest,
            condition_id=coordinate.condition_id,
            replication_ordinal=coordinate.replication_ordinal,
        ),
        condition_id=coordinate.condition_id,
        replication_ordinal=coordinate.replication_ordinal,
        ordering_index=coordinate.ordering_index,
        factor_levels=factor_levels,
        parameter_bindings=parameter_bindings,
        stochastic_seeds=_build_seeds(
            spec,
            source_set_digest=source_set_digest,
            condition_id=coordinate.condition_id,
            replication_ordinal=coordinate.replication_ordinal,
        ),
        scenario_snapshot_digest=scenario_snapshot_digest,
        capture_spec_refs=capture_spec_refs,
    )


def _expand_flat(
    spec: ExperimentSpecModel,
    *,
    source_set_digest: str,
    capture_spec_refs: tuple[str, ...],
) -> tuple[PlannedTrial, ...]:
    """Expand a flat (unconditioned) run_plan into target_run_count independently-replicated trials."""
    target_run_count = spec.run_plan.target_run_count
    return tuple(
        _build_trial(
            spec,
            source_set_digest=source_set_digest,
            coordinate=_TrialCoordinate(condition_id=None, replication_ordinal=ordinal, ordering_index=ordinal),
            factor_levels=(),
            parameter_bindings=(),
            condition_snapshot_digests=None,
            capture_spec_refs=capture_spec_refs,
        )
        for ordinal in range(target_run_count)
    )


def _expand_condition(
    spec: ExperimentSpecModel,
    *,
    source_set_digest: str,
    condition_snapshot_digests: Mapping[str, str] | None,
    capture_spec_refs: tuple[str, ...],
) -> tuple[PlannedTrial, ...]:
    """Expand a condition allocation into condition-major-replication-ordered trials, one per condition/replication."""
    allocation = spec.run_plan.allocation
    trials: list[PlannedTrial] = []
    ordering_index = 0
    # Authored order (`compared_conditions`) is the outer loop; condition
    # dict/key insertion order (`condition_assignments`) never affects the
    # result because each condition is looked up by ID, not iterated.
    for condition_id in allocation.compared_conditions:
        assignment = allocation.condition_assignments[condition_id]
        factor_levels = tuple(sorted(assignment.factor_levels.items()))
        parameter_bindings = tuple(
            sorted((parameter.name, parameter.value) for parameter in assignment.required_parameters)
        )
        for replication_ordinal in range(allocation.target_runs_per_condition):
            trials.append(
                _build_trial(
                    spec,
                    source_set_digest=source_set_digest,
                    coordinate=_TrialCoordinate(
                        condition_id=condition_id,
                        replication_ordinal=replication_ordinal,
                        ordering_index=ordering_index,
                    ),
                    factor_levels=factor_levels,
                    parameter_bindings=parameter_bindings,
                    condition_snapshot_digests=condition_snapshot_digests,
                    capture_spec_refs=capture_spec_refs,
                )
            )
            ordering_index += 1
    return tuple(trials)


def _trial_projection(trial: PlannedTrial) -> dict[str, object]:
    """Project one PlannedTrial into its canonical-JSON-ready dict shape."""
    return {
        "planned_trial_id": trial.planned_trial_id,
        "condition_id": trial.condition_id,
        "replication_ordinal": trial.replication_ordinal,
        "ordering_index": trial.ordering_index,
        # Represented as JSON objects (not arrays of pairs): RFC 8785
        # sorts object member names, so this is where "sort semantically
        # unordered maps" is actually enforced for the persisted bytes,
        # independent of the in-memory tuple already being pre-sorted.
        "factor_levels": dict(trial.factor_levels),
        "parameter_bindings": dict(trial.parameter_bindings),
        "stochastic_seeds": dict(trial.stochastic_seeds),
        "scenario_snapshot_digest": trial.scenario_snapshot_digest,
        "capture_spec_refs": list(trial.capture_spec_refs),
    }


def _canonicalize(
    *,
    policy_version: str,
    source_set_digest: str,
    ordering_kind: OrderingKind,
    trials: tuple[PlannedTrial, ...],
) -> tuple[bytes, str, str]:
    """Canonicalize the plan projection to RFC 8785 bytes and derive (canonical_bytes, plan_digest, plan_id)."""
    projection = {
        "plan_schema": _PLAN_PROJECTION_SCHEMA,
        "policy_version": policy_version,
        "source_set_digest": source_set_digest,
        "ordering_kind": ordering_kind.value,
        # The trial sequence itself is an authored-meaningful ordered list
        # (execution order) and stays a JSON array.
        "trials": [_trial_projection(trial) for trial in trials],
    }
    canonical_bytes = rfc8785.dumps(projection)
    digest_hex = hashlib.sha256(canonical_bytes).hexdigest()
    plan_digest = f"sha256:{digest_hex}"
    plan_id = _PLAN_ID_PREFIX + digest_hex
    return canonical_bytes, plan_digest, plan_id


def expand_trial_plan(
    spec: ExperimentSpecModel,
    *,
    source_set_digest: str,
    condition_snapshot_digests: Mapping[str, str] | None = None,
    policy: AdmissionPolicy,
) -> TrialPlan:
    """Pure expansion of an admitted spec's ``run_plan`` into an immutable :class:`TrialPlan`.

    ``source_set_digest`` and ``condition_snapshot_digests`` are supplied by
    the caller (a later admission stage) — this function does no artifact
    resolution or digesting of its own beyond the plan projection itself.

    Raises :class:`AdmissionRejection` when the planned trial count would
    exceed ``policy.max_allocation_size``, a stochastic control's role does
    not map to a supported controller policy, or the allocation's free-text
    ``allocation_method`` does not resolve to a usable ordering.
    """
    _validate_stochastic_controls(spec, policy=policy)
    ordering_kind = _resolve_ordering_kind(spec, policy=policy)
    capture_refs = _capture_spec_refs(spec)

    if ordering_kind is OrderingKind.FLAT:
        total = spec.run_plan.target_run_count
    else:
        allocation = spec.run_plan.allocation
        total = len(allocation.compared_conditions) * allocation.target_runs_per_condition

    # Enforced BEFORE allocating the trial list itself.
    if total > policy.max_allocation_size:
        raise _reject(
            _CODE_ALLOCATION_TOO_LARGE,
            _ADDRESS_RUN_PLAN,
            "planned trial count exceeds the configured allocation size limit",
        )

    if ordering_kind is OrderingKind.FLAT:
        trials = _expand_flat(spec, source_set_digest=source_set_digest, capture_spec_refs=capture_refs)
    else:
        trials = _expand_condition(
            spec,
            source_set_digest=source_set_digest,
            condition_snapshot_digests=condition_snapshot_digests,
            capture_spec_refs=capture_refs,
        )

    ids = [trial.planned_trial_id for trial in trials]
    if len(set(ids)) != len(ids):
        raise AssertionError("planned_trial_id collision within one trial plan")

    canonical_bytes, plan_digest, plan_id = _canonicalize(
        policy_version=policy.policy_version,
        source_set_digest=source_set_digest,
        ordering_kind=ordering_kind,
        trials=trials,
    )

    return TrialPlan(
        plan_id=plan_id,
        policy_version=policy.policy_version,
        source_set_digest=source_set_digest,
        ordering_kind=ordering_kind,
        trials=trials,
        canonical_bytes=canonical_bytes,
        plan_digest=plan_digest,
    )
