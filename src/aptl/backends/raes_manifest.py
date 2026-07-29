"""APTL RAES backend manifest.

APTL publishes its runtime-target capability declaration as the canonical RAES
``backend-manifest-v2`` surface (``raes_backend_protocols.capabilities``), not an
APTL-local approximation. The manifest is what the RAES planner's
realization-support gate and ``raes conformance backend --profile
full-remote-control-plane`` validate against, so it must declare APTL's real
provisioning, orchestration, evaluation, and participant-runtime capability
against the published controlled vocabularies and contract authority — anything
less is rejected by the conformance corpus.

APTL is a full remote-control-plane backend: it realizes RAES provisioning plans
into Docker Compose profiles, exposes its scenario runtime engine (RTE-001)
workflow drive surface through the portable ``workflow-result-envelope-v1`` and
``workflow-history-event-stream-v1`` contracts (see
``aptl.backends.raes_orchestrator.AptlOrchestrator``), publishes objective and
condition evaluation through ``evaluation-result-envelope-v1`` and
``evaluation-history-event-stream-v1`` (see
``aptl.backends.raes_evaluator.AptlEvaluator``), and exposes a bounded
green/red/blue participant runtime through the participant episode and
behavior-history contracts. It does not declare the deprecated SDL scoring chain
(``metrics``/``evaluations``/``tlos``/``goals``) as an APTL runtime capability.
"""

from __future__ import annotations

from raes_backend_protocols.capabilities import (
    BackendManifest,
    EvaluatorCapabilities,
    OrchestratorCapabilities,
    ParticipantFeatureSupport,
    ParticipantRuntimeCapabilities,
    ProvisionerCapabilities,
)
from raes_backend_protocols.manifest import backend_manifest_v2_model
from raes_contracts.apparatus import (
    ConceptBinding,
    RealizationSupportDeclaration,
    RealizationSupportMode,
)
from raes_contracts.contracts import (
    BackendManifestV2Model,
    BindingOwnerModel,
    BindingScalarType,
    ConfigurationTargetDeclarationModel,
    ConfigurationTargetRegistryModel,
    LiteralBindingValueModel,
)
from aptl.backends.raes_artifact_mechanisms import aptl_artifact_mechanisms
from raes_contracts.vocabulary import (
    ParticipantFeatureSupportLevel,
    WorkflowFeature,
    WorkflowStatePredicateFeature,
)

try:
    from raes_contracts.manifest_authority import BACKEND_SUPPORTED_CONTRACT_IDS
except ImportError:
    # Older RAES packages still expose validation without manifest authority.
    BACKEND_SUPPORTED_CONTRACT_IDS = ()

from aptl.backends.raes_participant_runtime import PARTICIPANT_ACTION_ADDRESS
from aptl.core.experiment.capture_registry import (
    DEFAULT_COLLECTOR_REGISTRY,
    OBSERVATION_EVIDENCE_CONTRACTS,
)

APTL_RAES_TARGET_NAME = "aptl"
APTL_RAES_TARGET_VERSION = "0.1.0"
APTL_EXPERIMENT_ACTION_TIMEOUT_TARGET = (
    "participant-runtime.action-timeout-seconds"
)

_EXPERIMENT_CONFIGURATION_REGISTRY = ConfigurationTargetRegistryModel(
    owner=BindingOwnerModel(
        contract_id="backend-manifest/v2",
        contract_version="1",
        validator_id="aptl-configuration",
        validator_version="1",
    ),
    targets={
        APTL_EXPERIMENT_ACTION_TIMEOUT_TARGET: ConfigurationTargetDeclarationModel(
            target_id=APTL_EXPERIMENT_ACTION_TIMEOUT_TARGET,
            value_type=BindingScalarType.INTEGER,
            allowed_value_kinds=["literal"],
            sensitivity="internal",
            default=LiteralBindingValueModel(kind="literal", value=120),
        )
    },
)

# The reference RAES processor whose provisioning-plan output APTL realizes.
_COMPATIBLE_PROCESSORS = frozenset({"raes-reference-processor"})

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
        "participant-control-occurrence-v1",
        "participant-crossing-occurrence-v1",
        "participant-lifecycle-event-v1",
        "participant-observation-envelope-v1",
        "participant-shared-state-record-v1",
        "participant-joint-action-record-v1",
        "participant-time-management-context-v1",
    }
)

_SUPPORTED_CONTRACT_VERSIONS = _BASE_SUPPORTED_CONTRACT_VERSIONS | (
    _CURRENT_PARTICIPANT_CONTRACT_VERSIONS & frozenset(BACKEND_SUPPORTED_CONTRACT_IDS)
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
# the portable evaluation result/history contracts. RAES ADR-073 moves graded
# scoring out of the authored SDL surface, so the manifest deliberately does not
# claim support for the OCR scoring chain (`metrics`/`evaluations`/`tlos`/`goals`).
_EVALUATOR = EvaluatorCapabilities(
    name="aptl-rte-evaluator",
    supported_sections=frozenset({"conditions", "objectives"}),
    supports_scoring=False,
    supports_objectives=True,
)

# Participant runtime capability declaration. APTL realizes the bounded
# green/red/blue research surface through RAES-owned episode, exact action, and
# observation-boundary contracts. This does not claim multi-party coordination,
# autonomous scheduling, or a role beyond the three implemented compartments.
_PARTICIPANT_RUNTIME = ParticipantRuntimeCapabilities(
    name="aptl-participant-runtime",
    supported_participant_roles=frozenset({"green", "red", "blue"}),
    supported_behavior_features=frozenset(
        {"action_contracts", "observation_boundaries", "behavior_history"}
    ),
    supported_interaction_features=frozenset({"shared_state_change"}),
    feature_support=(
        ParticipantFeatureSupport(
            feature="x-paper:boundary-negative-evidence",
            support_level=ParticipantFeatureSupportLevel.EXACT,
        ),
        ParticipantFeatureSupport(
            feature="x-paper:wazuh-evidence",
            support_level=ParticipantFeatureSupportLevel.EXACT,
        ),
    ),
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
    supported_os_families=frozenset({"linux"}),
    supported_content_types=frozenset({"dataset", "directory", "file"}),
    # Manifest honesty (#577, ADR-046 addendum): advertise only the account
    # features the backend materializes AND verifies by read-after-write — the
    # non-secret fields the typed DeploymentAccountRealization carries. auth_method
    # / home / shell are neither carried nor realized, so they are not claimed;
    # an account placement that exercises one is a blocking RAES diagnostic, not
    # a silently dropped field. No scenario declares those terms today.
    supported_account_features=frozenset({"disabled", "groups", "mail", "spn"}),
    # The Samba AD provider realizes and read-verifies the operational
    # scenario's domain-bound accounts and SPNs (#577). RAES 0.23 makes that
    # domain profile an explicit admission capability rather than inferring it
    # from account fields.
    supported_domain_profiles=frozenset({"active_directory"}),
    # RAES ACLs pass through the typed realization surface to separate,
    # owner-scoped nftables tables. The backend rejects unsupported dual-stack
    # inputs, applies replacements atomically, and reads back every rule before
    # reporting success.
    supports_acls=True,
    supports_accounts=True,
    supports_generated_artifacts=True,
    supports_persistent_volumes=True,
)

# What APTL realizes from a provisioning plan, and how. APTL matches declared
# capabilities against its provisioner support and discloses the result through
# the backend-manifest / operation-status / runtime-snapshot contracts. The
# constrained-kind set is intentionally narrower than the provisioner vocabulary:
# RAES 0.21.x publishes runtime concern paths for node type, OS family, and
# content type, but only OS family is currently expressible by APTL's regression
# scenario as a constrained (processor-derived) requirement. Node/content exact
# requirements are covered by ``declared-capability-match``; account features are
# realized through the account provider's typed read-after-write path but are not
# yet a RAES runtime realization concern.
#
# ``artifact_mechanisms`` declares which RAES artifact-satisfaction routes APTL
# can admit (ADR-050, RAES ADR-098). It is deliberately narrow: a mechanism is
# advertised only once APTL can both materialize it and read the result back
# (SEM-218 I4). ``support_mode`` stays CONSTRAINED because APTL cannot honestly
# realize an open artifact concern; an ``open`` requirement is refused with
# ``artifact.unsupported-open-realization`` rather than silently chosen for.
#
# ``source-artifact`` appears on the mechanism's ``supported_requirement_kinds``
# and on ``supported_constraint_kinds``, but deliberately NOT on
# ``supported_exact_requirement_kinds``. The two SEM-218 branches differ: the
# exact branch keys on the single ``declared-capability-match`` kind regardless
# of the requirement's own kind, so listing it there would claim a capability the
# gate never consults, while the constrained branch keys on the requirement's own
# kind and so genuinely needs it. The constrained claim is backed by the
# per-component build mechanism and its read-after-write of the built image.
_REALIZATION_SUPPORT = (
    RealizationSupportDeclaration(
        domain="runtime-realization",
        support_mode=RealizationSupportMode.CONSTRAINED,
        supported_constraint_kinds=frozenset({"os-family", "source-artifact"}),
        supported_exact_requirement_kinds=frozenset({"declared-capability-match"}),
        disclosure_kinds=frozenset(
            {"backend-manifest-v2", "operation-status-v1", "runtime-snapshot-v1"}
        ),
        artifact_mechanisms=list(aptl_artifact_mechanisms()),
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
    ConceptBinding(
        scope="capabilities.provisioner.supported_domain_profiles",
        family="identities",
    ),
)


def create_aptl_manifest() -> BackendManifest:
    """Return APTL's canonical full remote-control-plane backend manifest.

    The ``observation`` capability is an aggregate projection of the code-owned
    collector registry (EXP-010 / issue #752), NOT a hand-maintained matrix.
    :data:`~aptl.core.experiment.capture_registry.DEFAULT_COLLECTOR_REGISTRY`
    is empty until a capture capability is genuinely backed end-to-end, so the
    projection is ``None`` and no observation is declared — the honest EXP-002
    posture. When (EXP-010 PR 2) real registrations turn the projection on, the
    RAES ``observation_capability_contract_gaps`` invariant requires the
    capture-spec/evidence-record/derived-measure/experiment-run contracts in
    ``supported_contract_versions``, so they are added exactly then and never
    speculatively.
    """
    observation = DEFAULT_COLLECTOR_REGISTRY.observation_projection()
    supported_contract_versions = _SUPPORTED_CONTRACT_VERSIONS
    capability_options: dict[str, object] = {}
    if observation is not None:
        supported_contract_versions = (
            supported_contract_versions | OBSERVATION_EVIDENCE_CONTRACTS
        )
        capability_options["observation"] = observation
    return BackendManifest(
        name=APTL_RAES_TARGET_NAME,
        version=APTL_RAES_TARGET_VERSION,
        supported_contract_versions=supported_contract_versions,
        compatible_processors=_COMPATIBLE_PROCESSORS,
        realization_support=_REALIZATION_SUPPORT,
        concept_bindings=_CONCEPT_BINDINGS,
        provisioner=_PROVISIONER,
        orchestrator=_ORCHESTRATOR,
        evaluator=_EVALUATOR,
        participant_runtime=_PARTICIPANT_RUNTIME,
        **capability_options,
    )


def create_aptl_binding_manifest_model(
    manifest: BackendManifest | None = None,
) -> BackendManifestV2Model:
    """Return the canonical backend manifest with its closed binding registry."""

    selected = manifest if manifest is not None else create_aptl_manifest()
    if (
        selected.name != APTL_RAES_TARGET_NAME
        or selected.version != APTL_RAES_TARGET_VERSION
    ):
        raise ValueError(
            "APTL binding registry requires the canonical APTL backend identity"
        )
    payload = backend_manifest_v2_model(selected).model_dump(mode="json")
    payload["supported_contract_versions"] = sorted(
        {
            *payload["supported_contract_versions"],
            "experiment-binding-descriptors-v1",
        }
    )
    payload["configuration_registry"] = _EXPERIMENT_CONFIGURATION_REGISTRY.model_dump(
        mode="json"
    )
    return BackendManifestV2Model.model_validate(payload)
