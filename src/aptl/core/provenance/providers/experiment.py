"""Admitted experiment/trial identity provenance (REP-003 / issue #452).

Answers "which scenario and which admitted plan produced this run" from the
identities admission already accepted — the persisted
:class:`~aptl.core.experiment.trial_plan_models.TrialPlan`. The preflight is
explicit that seal-time collection must not reopen the authored scenario,
recompute bindings against current configuration, or infer a run from the
active directory: a display name, source path, or module lock digest is not a
canonical scenario snapshot, and re-deriving one at seal time would describe
the present rather than the run.

Scenario parameter VALUES are deliberately not recorded. ADR-044 already
establishes that APTL does not persist raw scenario bindings or value-bearing
provenance; the plan's canonical digests identify the binding without
disclosing it.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from aptl.core.provenance.identity import (
    ProvenanceIdentityError,
    ProvenanceLeaf,
    derive_identity,
)
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult

log = logging.getLogger(__name__)

#: The code-owned provider id for admitted experiment identity.
EXPERIMENT_PROVIDER_ID = "experiment"

#: Identity domain for the plan and per-trial leaves.
_DOMAIN = "experiment"


def _plan_projection(plan: object) -> dict[str, object]:
    """Return the admitted plan's identity fields."""
    return {
        "plan_id": getattr(plan, "plan_id", None),
        "policy_version": getattr(plan, "policy_version", None),
        "source_set_digest": getattr(plan, "source_set_digest", None),
        "plan_digest": getattr(plan, "plan_digest", None),
    }


def _trial_projection(trial: object) -> dict[str, object]:
    """Return one planned trial's identity fields.

    ``stochastic_seeds`` are recorded by control id and seed digest: the seed
    is itself a derived identity in the admitted plan, and it is what makes a
    run's randomness reconstructable.
    """
    seeds = getattr(trial, "stochastic_seeds", ()) or ()
    captures = getattr(trial, "capture_spec_refs", ()) or ()
    return {
        "planned_trial_id": getattr(trial, "planned_trial_id", None),
        "condition_id": getattr(trial, "condition_id", None),
        "replication_ordinal": getattr(trial, "replication_ordinal", None),
        "scenario_snapshot_digest": getattr(trial, "scenario_snapshot_digest", None),
        "capture_spec_refs": sorted(str(ref) for ref in captures),
        "stochastic_seeds": sorted(
            {"control_id": str(control), "seed": str(seed)} for control, seed in seeds
        )
        if seeds
        else [],
    }


def _binding_projection(binding: object) -> dict[str, object]:
    """Return one admitted capture binding's collector and channel identity.

    This is the collector-selection fact the requirement asks for: WHICH
    trusted collector registration was bound, at which declared implementation
    version, against which authored measurement channel. A registry
    declaration alone is not proof a collector ran, so the pinned
    ``effective_config_digest`` from the admitted binding is recorded rather
    than re-read from the current registry.
    """
    return {
        "capture_spec_id": getattr(binding, "capture_spec_id", None),
        "requirement_id": getattr(binding, "requirement_id", None),
        "registration_id": getattr(binding, "registration_id", None),
        "implementation_version": getattr(binding, "implementation_version", None),
        "contract_version": getattr(binding, "contract_version", None),
        "channel_ref_id": getattr(binding, "channel_ref_id", None),
        "channel_ref_version": getattr(binding, "channel_ref_version", None),
        "channel_kind": getattr(binding, "channel_kind", None),
        "effective_config_digest": getattr(binding, "effective_config_digest", None),
    }


class AdmittedExperimentProvider:
    """Collects the admitted plan's, trials', and capture bindings' identities."""

    provider_id = EXPERIMENT_PROVIDER_ID

    def __init__(self, plan: object | None):
        self._plan = plan

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Project the admitted plan into leaves without re-admitting anything."""
        plan = self._plan
        if plan is None:
            # No admitted plan is a real fact about this run (a plain lab
            # start), not a source that failed. It must never become a
            # fabricated plan identity.
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.UNAVAILABLE,
                detail="source not present",
            )

        trials: Sequence[object] = tuple(getattr(plan, "trials", ()) or ())
        bindings: Sequence[object] = tuple(getattr(plan, "capture_bindings", ()) or ())
        # +1 for the plan leaf itself.
        if len(trials) + len(bindings) + 1 > context.max_entries:
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.TRUNCATED,
                detail="entry limit reached",
            )

        collectors: list[dict[str, object]] = []
        try:
            leaves = [
                ProvenanceLeaf("plan", derive_identity(_DOMAIN, _plan_projection(plan)))
            ]
            for trial in trials:
                projection = _trial_projection(trial)
                trial_id = projection["planned_trial_id"]
                leaves.append(
                    ProvenanceLeaf(f"trial/{trial_id}", derive_identity(_DOMAIN, projection))
                )
            for binding in bindings:
                projection = _binding_projection(binding)
                capture_id = projection["capture_spec_id"]
                requirement_id = projection["requirement_id"]
                leaves.append(
                    ProvenanceLeaf(
                        f"capture/{capture_id}/{requirement_id}",
                        derive_identity(_DOMAIN, projection),
                    )
                )
                collectors.append(projection)
        except (ProvenanceIdentityError, TypeError, ValueError):
            log.warning("run-provenance: admitted plan projection could not be identified")
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.FAILED,
                detail="owner reported failure",
            )

        if context.expired():
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.TIMED_OUT,
                detail="deadline exceeded",
            )

        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=tuple(sorted(leaves)),
            payload={
                **_plan_projection(plan),
                "trial_count": len(trials),
                "collectors": collectors,
            },
        )
