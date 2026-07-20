"""ACES capture-requirement admission via the collector registry (ADR-047
"Apparatus and capture capability admission"; EXP-010 / issue #752).

EXP-002 shipped an empty ``SUPPORTED_CAPTURE_CAPABILITIES`` table here. EXP-010
evolves that into the single versioned :class:`~aptl.core.experiment.
capture_registry.CollectorRegistry` (its own module), and this module becomes
the thin admission entry point that binds every authored capture requirement
against that registry.

FAIL-CLOSED BASELINE (unchanged from #438): a capture requirement is admitted
ONLY when a trusted registration in the resolved registry deterministically
covers every requirement axis (contract version, channel identity/version,
capture kind/scope, window semantics, media types, artifact roles, sensitivity,
integrity, redaction, retention, loss disclosure). The mere existence of a
best-effort collector function is never evidence of support. The production
:data:`~aptl.core.experiment.capture_registry.DEFAULT_COLLECTOR_REGISTRY` is
EMPTY, so every capture-bearing input still fails closed until EXP-010 PR 2
lands real registrations together with their acquisition adapters.

Admission is all-or-nothing: the moment ANY requirement across ANY spec is
unbound, admission is rejected (naming the unsupported ``capture_kind`` /
``capture_scope``) — never a partial binding. Authored requirements are
required by default; a degradation is admitted only when
``policy.accepted_capture_limitations`` explicitly accepts it, and that
acceptance is annotated onto the bound requirement's plan binding (never
inferred).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable

from aces_contracts.contracts import ExperimentCaptureSpecModel

from aptl.core.experiment.capture_registry import (
    DEFAULT_COLLECTOR_REGISTRY,
    CaptureBinding,
    CollectorRegistry,
)
from aptl.core.experiment.errors import AdmissionRejection, diagnostic
from aptl.core.experiment.policy import AdmissionPolicy

_CODE_CAPTURE_UNSUPPORTED = "aptl.experiment-admission.capture-requirement-unsupported"


def _apply_limitation(
    binding: CaptureBinding, *, capture_spec_id: str, policy: AdmissionPolicy
) -> CaptureBinding:
    """Return binding annotated with any policy-accepted degradation, else unchanged.

    The acceptance is keyed by the fully-qualified
    ``"{capture_spec_id}.{requirement_id}"``; when present its stable
    limitation code and comparability disclosure are pinned onto the binding so
    the degradation travels in the plan bytes and is auditable.
    """
    key = f"{capture_spec_id}.{binding.requirement_id}"
    acceptance = policy.accepted_capture_limitations.get(key)
    if acceptance is None:
        return binding
    return dataclasses.replace(
        binding,
        accepted_limitation=acceptance.limitation_code,
        comparability_disclosure_ref=acceptance.comparability_disclosure_ref,
    )


def bind_capture_requirements(
    capture_specs: Iterable[ExperimentCaptureSpecModel],
    *,
    registry: CollectorRegistry = DEFAULT_COLLECTOR_REGISTRY,
    policy: AdmissionPolicy,
) -> tuple[CaptureBinding, ...]:
    """Bind every capture requirement in ``capture_specs`` to an immutable binding.

    Returns the tuple of :class:`CaptureBinding` values, sorted by stable
    identity ``(capture_spec_id, requirement_id)`` so the ACES
    ``capture_requirements`` dict's iteration order (a semantically unordered
    map) never leaks into the pinned plan digest (ADR-047 "sort semantically
    unordered maps/sets"). They are pinned in the canonical trial-plan bytes
    before any range mutation.

    Raises :class:`~aptl.core.experiment.errors.AdmissionRejection` (fail
    closed, naming the unsupported ``capture_kind`` / ``capture_scope``) the
    moment ANY requirement is not covered by a trusted registration — admission
    is all-or-nothing, never a partial binding. An empty ``capture_specs``
    iterable (no capture spec resolved at all) returns an empty tuple without
    rejecting; ``ExperimentCaptureSpecModel`` itself requires at least one
    entry in ``capture_requirements``, so an individual resolved spec can never
    be "empty".
    """
    bindings: list[CaptureBinding] = []
    diagnostics = []
    for spec in capture_specs:
        for requirement_id, requirement in spec.capture_requirements.items():
            binding = registry.match(spec, requirement)
            if binding is None:
                address = f"capture_spec.{spec.capture_spec_id}.capture_requirements.{requirement_id}"
                diagnostics.append(
                    diagnostic(
                        _CODE_CAPTURE_UNSUPPORTED,
                        address,
                        "capture requirement (capture_kind="
                        f"{requirement.capture_kind!r}, capture_scope={requirement.capture_scope!r}) "
                        "is not covered by a declared collector registration",
                    )
                )
                continue
            bindings.append(
                _apply_limitation(binding, capture_spec_id=spec.capture_spec_id, policy=policy)
            )

    if diagnostics:
        raise AdmissionRejection(tuple(diagnostics))
    return tuple(sorted(bindings, key=lambda binding: (binding.capture_spec_id, binding.requirement_id)))
