"""APTL ACES backend manifest.

APTL publishes its runtime-target capability declaration as the canonical ACES
``backend-manifest-v2`` surface (``aces_backend_protocols.capabilities``), not an
APTL-local approximation. The manifest is what the ACES planner's
realization-support gate and ``aces conformance backend --profile
full-remote-control-plane`` validate against, so it must declare APTL's real
provisioning, orchestration, evaluation, and participant-runtime capability
against the published controlled vocabularies and contract authority — anything
less is rejected by the conformance corpus.

APTL is a full remote-control-plane backend: it realizes ACES provisioning plans
into Docker Compose profiles, exposes its scenario runtime engine (RTE-001)
workflow drive surface through the portable ``workflow-result-envelope-v1`` and
``workflow-history-event-stream-v1`` contracts (see
``aptl.backends.aces_orchestrator.AptlOrchestrator``), publishes objective and
condition evaluation through ``evaluation-result-envelope-v1`` and
``evaluation-history-event-stream-v1`` (see
``aptl.backends.aces_evaluator.AptlEvaluator``), and exposes a narrow red
participant runtime through the participant episode and behavior-history
contracts.
"""

from __future__ import annotations

from aces_backend_protocols.capabilities import (
    BackendManifest,
    EvaluatorCapabilities,
    OrchestratorCapabilities,
    ParticipantRuntimeCapabilities,
    ProvisionerCapabilities,
)
from aces_contracts.apparatus import (
    ConceptBinding,
    RealizationSupportDeclaration,
    RealizationSupportMode,
)
from aces_contracts.vocabulary import WorkflowFeature, WorkflowStatePredicateFeature

try:
    from aces_contracts.manifest_authority import BACKEND_SUPPORTED_CONTRACT_IDS
except ImportError:  # pragma: no cover - older ACES packages still expose validation.
    BACKEND_SUPPORTED_CONTRACT_IDS = ()

from aptl.backends.aces_participant_runtime import PARTICIPANT_ACTION_ADDRESS

APTL_ACES_TARGET_NAME = "aptl"
APTL_ACES_TARGET_VERSION = "0.1.0"

# The reference ACES processor whose provisioning-plan output APTL realizes.
_COMPATIBLE_PROCESSORS = frozenset({"aces-reference-processor"})

# Full remote-control-plane contract surface. The profile requires the planning,
# operation/status, runtime-snapshot, workflow, evaluation, and participant
# episode/behavior contracts. APTL consumes the plan contracts and emits the
# result/history contracts through its adapters.
_BASE_SUPPORTED_CONTRACT_VERSIONS = frozenset(
    {
        "backend-manifest-v2",
        "provisioning-plan-v1",
        "orchestration-plan-v1",
        "evaluation-plan-v1",
        "operation-receipt-v1",
        "operation-status-v1",
        "runtime-snapshot-v1",
        "workflow-result-envelope-v1",
        "workflow-history-event-stream-v1",
        "evaluation-result-envelope-v1",
        "evaluation-history-event-stream-v1",
        "participant-episode-state-envelope-v1",
        "participant-episode-history-event-stream-v1",
        "participant-behavior-history-event-stream-v1",
    }
)

_CURRENT_PARTICIPANT_CONTRACT_VERSIONS = frozenset(
    {
        "participant-lifecycle-event-v1",
        "participant-observation-envelope-v1",
        "participant-shared-state-record-v1",
        "participant-joint-action-record-v1",
        "participant-time-management-context-v1",
    }
)

_SUPPORTED_CONTRACT_VERSIONS = _BASE_SUPPORTED_CONTRACT_VERSIONS | (
    _CURRENT_PARTICIPANT_CONTRACT_VERSIONS
    & frozenset(BACKEND_SUPPORTED_CONTRACT_IDS)
)

# Orchestrator capability declaration. APTL's RTE-001 runtime engine drives
# workflows with objective, branching (`if` -> decision), parallel
# (-> parallel-barrier), and `on-error` (-> failure-transitions) control flow,
# with step-outcome predicates (-> outcome-matching). Those are the workflow
# control features APTL can faithfully realize and report through the portable
# workflow result/history contracts, so the manifest declares exactly that set
# — not the switch/retry/call/cancellation/timeouts/compensation features APTL
# does not drive (scenarios using those get an explicit planner diagnostic).
_ORCHESTRATOR = OrchestratorCapabilities(
    name="aptl-rte-orchestrator",
    supported_sections=frozenset({"workflows"}),
    supports_workflows=True,
    supported_workflow_features=frozenset(
        {
            WorkflowFeature.DECISION,
            WorkflowFeature.PARALLEL_BARRIER,
            WorkflowFeature.FAILURE_TRANSITIONS,
        }
    ),
    supported_workflow_state_predicates=frozenset(
        {WorkflowStatePredicateFeature.OUTCOME_MATCHING}
    ),
)

# Evaluator capability declaration. APTL's RTE-001 runtime evaluates scenario
# conditions (healthchecks realized during provisioning) and objectives through
# the portable evaluation result/history contracts. Scoring sections are
# declared because SCN-007 scoring resources compile into the same evaluation
# plan surface even though live score progression remains #514 follow-on work.
_EVALUATOR = EvaluatorCapabilities(
    name="aptl-rte-evaluator",
    supported_sections=frozenset({"conditions", "objectives", "goals", "evaluations"}),
    supports_scoring=True,
    supports_objectives=True,
)

# Participant runtime capability declaration. The current proof drives a single
# red participant action from Kali against a realized victim container and emits
# participant episode plus behavior-history snapshot surfaces. It does not claim
# blue/green/white roles or multi-party coordination semantics.
_PARTICIPANT_RUNTIME = ParticipantRuntimeCapabilities(
    name="aptl-participant-runtime",
    supported_participant_roles=frozenset({"red"}),
    supported_behavior_features=frozenset({"behavior_history"}),
    supported_interaction_features=frozenset({"shared_state_change"}),
    constraints={
        "default_participant_action_address": PARTICIPANT_ACTION_ADDRESS,
        "backend_boundary": "DeploymentBackend.container_exec",
    },
)

# Provisioner capability declaration, using only published controlled-vocabulary
# terms (validated against contracts/concept-authority/controlled-vocabularies-v1).
_PROVISIONER = ProvisionerCapabilities(
    name="aptl-docker-compose-provisioner",
    supported_node_types=frozenset({"switch", "vm"}),
    supported_os_families=frozenset({"freebsd", "linux", "macos", "other", "windows"}),
    supported_content_types=frozenset({"dataset", "directory", "file"}),
    supported_account_features=frozenset(
        {"auth_method", "disabled", "groups", "home", "mail", "shell", "spn"}
    ),
    supports_acls=True,
    supports_accounts=True,
)

# What APTL realizes from a provisioning plan, and how. APTL matches declared
# capabilities against its provisioner support and discloses the result through
# the backend-manifest / operation-status / runtime-snapshot contracts.
_REALIZATION_SUPPORT = (
    RealizationSupportDeclaration(
        domain="runtime-realization",
        support_mode=RealizationSupportMode.CONSTRAINED,
        supported_constraint_kinds=frozenset(
            {"account-feature", "content-type", "node-type", "os-family"}
        ),
        supported_exact_requirement_kinds=frozenset({"declared-capability-match"}),
        disclosure_kinds=frozenset(
            {"backend-manifest-v2", "operation-status-v1", "runtime-snapshot-v1"}
        ),
        constraints={},
    ),
)

# Concept-authority bindings: which controlled-vocabulary family each
# provisioner capability scope draws its terms from.
_CONCEPT_BINDINGS = (
    ConceptBinding(
        scope="capabilities.provisioner.supported_node_types", family="assets"
    ),
    ConceptBinding(
        scope="capabilities.provisioner.supported_os_families", family="assets"
    ),
    ConceptBinding(
        scope="capabilities.provisioner.supported_content_types",
        family="tools-and-artifacts",
    ),
    ConceptBinding(
        scope="capabilities.provisioner.supported_account_features",
        family="identities",
    ),
)


def create_aptl_manifest() -> BackendManifest:
    """Return APTL's canonical full remote-control-plane backend manifest."""
    return BackendManifest(
        name=APTL_ACES_TARGET_NAME,
        version=APTL_ACES_TARGET_VERSION,
        supported_contract_versions=_SUPPORTED_CONTRACT_VERSIONS,
        compatible_processors=_COMPATIBLE_PROCESSORS,
        realization_support=_REALIZATION_SUPPORT,
        concept_bindings=_CONCEPT_BINDINGS,
        provisioner=_PROVISIONER,
        orchestrator=_ORCHESTRATOR,
        evaluator=_EVALUATOR,
        participant_runtime=_PARTICIPANT_RUNTIME,
    )
