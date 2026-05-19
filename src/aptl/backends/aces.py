"""APTL backend adapter for the ACES runtime contract surface (#310).

Phase A.1 scaffolding: this module exposes a shape-correct
``provisioning-only`` backend that the ACES conformance suite accepts, but
does NOT yet wire ``apply()`` through to APTL's deployment helpers.
Actionable plan operations (anything other than
:class:`~aces_processor.models.ChangeAction.UNCHANGED`) raise
:class:`ApplyNotImplementedError` so the unwiring is explicit. Plans
containing only ``UNCHANGED`` operations apply as no-op success — that
preserves idempotent re-apply behavior the control plane relies on.
Phase A.2 (next PR) replaces the raise with real orchestration calling
:func:`aptl.core.lab.orchestrate_lab_start` via
:class:`aptl.core.deployment.DeploymentBackend`, translating ACES
diagnostics into the existing :class:`aptl.core.lab_types.LabResult`
envelope per ADR-035 integration guardrails.

The module is import-side-effect-free; explicit
:func:`register` registration is required to add APTL to any ACES
:class:`~aces_processor.registry.BackendRegistry`.
"""

from __future__ import annotations

from importlib import metadata
from typing import Final

from aces_backend_protocols.capabilities import (
    BackendManifest,
    ProvisionerCapabilities,
)
from aces_contracts.apparatus import (
    ConceptBinding,
    RealizationSupportDeclaration,
    RealizationSupportMode,
)
from aces_processor.manifest import REFERENCE_PROCESSOR_NAME
from aces_processor.models import (
    ApplyResult,
    Diagnostic,
    ProvisioningPlan,
    RuntimeSnapshot,
)
from aces_processor.registry import (
    BackendRegistry,
    RuntimeTarget,
    RuntimeTargetComponents,
)

#: Backend name as registered with ACES. Matches ``backend-manifest-v2.identity.name``.
BACKEND_NAME: Final = "aptl"

#: ACES processor surface APTL declares compatibility with. Sourced from
#: :data:`aces_processor.manifest.REFERENCE_PROCESSOR_NAME` so a future
#: rename in ACES surfaces as a TypeError import-side rather than a silent
#: identity mismatch in the published manifest. Reviewed in codex
#: pre-push cycle 1 (#310).
COMPATIBLE_PROCESSOR: Final = REFERENCE_PROCESSOR_NAME

#: Required contract versions for the ``provisioning-only`` profile per
#: ``contracts/profiles/backend/provisioning-only.json`` in aces-sdl.
_PROVISIONING_ONLY_CONTRACTS: Final[frozenset[str]] = frozenset(
    {
        "backend-manifest-v2",
        "operation-receipt-v1",
        "operation-status-v1",
        "runtime-snapshot-v1",
    }
)


def _aptl_package_version(default: str = "0.0.0+unknown") -> str:
    """Return APTL's installed package version, or ``default`` if absent.

    The backend manifest's ``identity.version`` is a published compatibility
    contract; pinning it to a literal would lie as soon as the package
    version bumps. Matches the upstream stub pattern of deriving from
    installed metadata. Codex pre-push cycle 1 (#310).
    """
    try:
        return metadata.version("aptl")
    except metadata.PackageNotFoundError:
        return default


class ApplyNotImplementedError(NotImplementedError):
    """Phase A.1 marker: real ``apply()`` wiring lands in Phase A.2.

    A subclass of :class:`NotImplementedError` so callers can keep generic
    ``except NotImplementedError`` paths working while the test suite can
    pin the specific shape during the skeleton phase.
    """


class AptlProvisioner:
    """ACES ``Provisioner`` implementation for APTL (Phase A.1 skeleton).

    Conforms to :class:`aces_backend_protocols.protocols.Provisioner` by
    shape. Reconciliation against the APTL lab is NOT yet wired; plans
    with actionable operations surface as
    :class:`ApplyNotImplementedError` rather than silently no-op'ing.
    Idempotent re-applies (plans containing only ``UNCHANGED`` operations)
    succeed as a no-op so the control-plane's repeated-apply cycle works.
    """

    def validate(self, plan: ProvisioningPlan) -> list[Diagnostic]:
        """Return an empty diagnostic list.

        Phase A.1 does not yet inspect plans for APTL-specific feasibility;
        Phase A.2 adds capability checks (image availability, host
        inventory) here.
        """
        # ``plan`` intentionally unused at this skeleton stage. Touch it so
        # static analyzers don't flag the parameter as unused while keeping
        # the public Protocol signature stable.
        _ = plan
        return []

    def apply(self, plan: ProvisioningPlan, snapshot: RuntimeSnapshot) -> ApplyResult:
        """Apply a plan against the APTL lab.

        Phase A.1: idempotent re-applies (plans with no actionable
        operations) succeed as a no-op; any plan that includes a real
        change action raises :class:`ApplyNotImplementedError`. Phase A.2
        wires real reconciliation through
        :class:`aptl.core.deployment.DeploymentBackend`.
        """
        # `actionable_operations` filters out `ChangeAction.UNCHANGED`,
        # which is what the control plane emits when the snapshot already
        # matches the plan. Codex pre-push cycle 1 (#310) — the prior
        # raw-operations gate broke idempotent re-apply.
        if plan.actionable_operations:
            raise ApplyNotImplementedError(
                "AptlProvisioner.apply() Phase A.1 skeleton does not yet "
                "support actionable plans; real wiring lands in Phase A.2. "
                "See https://github.com/Brad-Edwards/aptl/issues/310."
            )
        # No actionable operations = nothing to reconcile, snapshot
        # returned unchanged. `changed_addresses=[]` is set explicitly so
        # test assertions exercise APTL's behavior, not the SDK's default
        # constructor (test-quality review cycle 1 T-002 #310). Phase A.2
        # will populate it with the addresses orchestrate_lab_start
        # actually touched.
        return ApplyResult(success=True, snapshot=snapshot, changed_addresses=[])


def create_aptl_manifest(*, version: str | None = None) -> BackendManifest:
    """Return APTL's :class:`BackendManifest` for the ``provisioning-only`` profile.

    ``version`` defaults to APTL's installed package version (see
    :func:`_aptl_package_version`); pass an explicit override only for
    tests that need to pin a specific identity. The four contract
    versions required by the profile are declared via
    :data:`_PROVISIONING_ONLY_CONTRACTS`. Capability terms come from
    ACES's controlled vocabulary; APTL's containerized lab hosts are
    modelled as ``vm`` nodes and APTL's per-segment Docker networks as
    ``switch`` nodes. The ``container`` term is absent from ACES's
    controlled vocabulary today — that trade-off is captured in
    ``docs/lessons/2026-05-19-aces-backend-skeleton.md``.
    """
    return BackendManifest(
        name=BACKEND_NAME,
        version=version if version is not None else _aptl_package_version(),
        compatible_processors=frozenset({COMPATIBLE_PROCESSOR}),
        supported_contract_versions=_PROVISIONING_ONLY_CONTRACTS,
        provisioner=ProvisionerCapabilities(
            name=f"{BACKEND_NAME}-provisioner",
            # `switch` covers APTL's per-segment Docker networks
            # (aptl-security, aptl-dmz, aptl-internal, aptl-redteam);
            # `vm` covers the containerized lab hosts. Codex pre-push
            # cycle 1 (#310) — without `switch` the planner rejects any
            # networked scenario.
            supported_node_types=frozenset({"vm", "switch"}),
            supported_os_families=frozenset({"linux", "windows"}),
            supported_content_types=frozenset({"file"}),
            supported_account_features=frozenset({"shell"}),
            max_total_nodes=None,
            supports_acls=False,
            supports_accounts=True,
        ),
        # Concept bindings tie the controlled-vocabulary scopes the
        # provisioner declares to their concept families. Only the
        # provisioner scopes are bound here since orchestrator and
        # evaluator are absent at the provisioning-only profile tier.
        concept_bindings=(
            ConceptBinding(
                scope="capabilities.provisioner.supported_node_types",
                family="assets",
            ),
            ConceptBinding(
                scope="capabilities.provisioner.supported_os_families",
                family="assets",
            ),
            ConceptBinding(
                scope="capabilities.provisioner.supported_content_types",
                family="tools-and-artifacts",
            ),
            ConceptBinding(
                scope="capabilities.provisioner.supported_account_features",
                family="identities",
            ),
        ),
        # Realization-support declaration: APTL is a CONSTRAINED backend —
        # it realizes scenario plans against the capability vocabulary
        # declared above, not arbitrary open-realization shapes. The
        # disclosure kinds are exactly the four contracts the
        # provisioning-only profile requires.
        realization_support=(
            RealizationSupportDeclaration(
                domain="runtime-realization",
                support_mode=RealizationSupportMode.CONSTRAINED,
                supported_constraint_kinds=frozenset(
                    {
                        "node-type",
                        "os-family",
                        "content-type",
                        "account-feature",
                    }
                ),
                supported_exact_requirement_kinds=frozenset(
                    {"declared-capability-match"}
                ),
                disclosure_kinds=frozenset(_PROVISIONING_ONLY_CONTRACTS),
            ),
        ),
    )


def _build_components(**config: object) -> RuntimeTargetComponents:
    """Construct the component bundle for the APTL target.

    ``provisioning-only`` declares only a Provisioner; orchestrator,
    evaluator, and participant_runtime are absent at this profile tier.
    This is the single source of truth for which roles APTL ships —
    :func:`create_aptl_target` and :func:`register` both go through here
    so a profile upgrade (Phase A.3/A.4) only edits this one factory.
    """
    _ = config  # reserved for Phase A.2 config plumbing
    return RuntimeTargetComponents(
        provisioner=AptlProvisioner(),
        orchestrator=None,
        evaluator=None,
        participant_runtime=None,
    )


def create_aptl_target(*, version: str | None = None, **config: object) -> RuntimeTarget:
    """Return APTL as an ACES :class:`RuntimeTarget`.

    Builds the manifest and component bundle once and passes the bundle
    through to :class:`RuntimeTarget` so a future profile upgrade only
    edits :func:`_build_components` — there's no parallel wiring path
    here that can drift. Codex pre-push cycle 1 (#310).
    """
    components = _build_components(**config)
    return RuntimeTarget(
        name=BACKEND_NAME,
        manifest=create_aptl_manifest(version=version),
        provisioner=components.provisioner,
        orchestrator=components.orchestrator,
        evaluator=components.evaluator,
        participant_runtime=components.participant_runtime,
    )


def register(registry: BackendRegistry, *, version: str | None = None) -> None:
    """Register APTL with an ACES :class:`BackendRegistry`.

    No auto-registration at import time — callers (CI, test harness,
    Phase B lab CLI) decide when to wire APTL into ACES. Matches the
    reference :func:`aces_backend_stubs.stubs.create_stub_target` /
    explicit-registration pattern.
    """
    registry.register(
        BACKEND_NAME,
        manifest_factory=lambda **cfg: create_aptl_manifest(version=version),
        components_factory=lambda **cfg: _build_components(**cfg),
    )
