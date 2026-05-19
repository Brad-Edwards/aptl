"""APTL backend adapter for the ACES runtime contract surface (#310).

APTL implements the ACES ``provisioning-only`` profile. ``apply()`` wires
through an :class:`aptl.core.deployment.DeploymentBackend` (passed at
construction); the backend's ``start()`` drives the lab and the resulting
:class:`aptl.core.lab_types.LabResult` is translated into an ACES
:class:`~aces_processor.models.ApplyResult`. Failure flows as a structured
diagnostic on the result (matching ACES's idiom) — apply() never raises.

When no backend is wired (the conformance-only path used by tests + the
``aces conformance backend`` advisory CI job) apply() returns a
diagnostic-bearing failure rather than driving real Docker.

The module is import-side-effect-free; explicit :func:`register` is
required to add APTL to any ACES :class:`~aces_processor.registry.BackendRegistry`.
"""

from __future__ import annotations

from importlib import metadata
from typing import TYPE_CHECKING, Final

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
    Severity,
)
from aces_processor.registry import (
    BackendRegistry,
    RuntimeTarget,
    RuntimeTargetComponents,
)

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

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


#: Default Docker Compose profile set APTL activates when an actionable
#: plan arrives without explicit profile selection. Matches the legacy
#: lab's full-profile bring-up.
DEFAULT_PROFILES: Final[tuple[str, ...]] = (
    "wazuh", "victim", "kali", "enterprise", "soc",
)


class AptlProvisioner:
    """ACES ``Provisioner`` driving APTL's lab via :class:`DeploymentBackend`.

    When ``backend`` is supplied, ``apply()`` calls ``backend.start()`` with
    the configured profile set and translates the resulting
    :class:`~aptl.core.lab_types.LabResult` into an ACES
    :class:`~aces_processor.models.ApplyResult`. Failure flows as a
    structured diagnostic on the result; ``apply()`` never raises (ADR-035
    user-visible-invariance contract + ACES idiom).

    When ``backend`` is None (conformance-only paths: tests, the advisory
    CI job, ``aces conformance backend`` runs), ``apply()`` returns a
    diagnostic-bearing failure for any actionable plan rather than
    accidentally drive Docker. Idempotent re-applies (plans containing only
    ``ChangeAction.UNCHANGED`` operations) succeed as a no-op regardless.
    """

    def __init__(
        self,
        *,
        backend: "DeploymentBackend | None" = None,
        profiles: tuple[str, ...] | list[str] = DEFAULT_PROFILES,
        build: bool = True,
    ) -> None:
        self._backend = backend
        self._profiles = list(profiles)
        self._build = build

    def validate(self, plan: ProvisioningPlan) -> list[Diagnostic]:
        """Pre-flight capability check against APTL's adapter.

        Emits no diagnostics today — the manifest's controlled vocabulary
        already gates plan feasibility at compile time. Host-inventory +
        image-cache probes will land here in a follow-on commit using
        ``self._backend`` state.
        """
        _ = plan
        return []

    def apply(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Reconcile the lab against ``plan`` and return an ``ApplyResult``.

        Failure surfaces as a structured diagnostic on the result, not as a
        raised exception. ``RuntimeManager`` would catch a raise and wrap
        it, but owning the diagnostic shape lets APTL preserve its error
        vocabulary across the cutover (per ADR-035).
        """
        if not plan.actionable_operations:
            return ApplyResult(
                success=True, snapshot=snapshot, changed_addresses=[]
            )

        if self._backend is None:
            return _failure_apply_result(
                snapshot,
                code="aptl.backend-not-wired",
                address="runtime.apply.provisioning",
                message=(
                    "AptlProvisioner has no DeploymentBackend wired; "
                    "construct via create_aptl_target(backend=...) to drive "
                    "the lab. Conformance-only paths use the no-backend "
                    "form intentionally."
                ),
            )

        lab_result = self._backend.start(self._profiles, build=self._build)
        if lab_result.success:
            return ApplyResult(
                success=True,
                snapshot=snapshot,
                changed_addresses=[
                    op.address for op in plan.actionable_operations
                ],
            )
        return _failure_apply_result(
            snapshot,
            code="aptl.lab-start-failed",
            address="runtime.apply.provisioning",
            message=(
                lab_result.error or lab_result.message
                or f"DeploymentBackend.start returned outcome={lab_result.outcome.value}"
            ),
        )


def _failure_apply_result(
    snapshot: RuntimeSnapshot,
    *,
    code: str,
    address: str,
    message: str,
) -> ApplyResult:
    """Build an ``ApplyResult(success=False, diagnostics=[...])`` envelope.

    Centralizes the failure shape so every apply-path failure carries
    APTL's error code namespace and a non-empty diagnostic.
    """
    return ApplyResult(
        success=False,
        snapshot=snapshot,
        diagnostics=[
            Diagnostic(
                code=code,
                domain="provisioning",
                address=address,
                message=message,
                severity=Severity.ERROR,
            )
        ],
        changed_addresses=[],
    )


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


def _build_components(
    *,
    backend: "DeploymentBackend | None" = None,
    profiles: tuple[str, ...] | list[str] = DEFAULT_PROFILES,
    build: bool = True,
    **_extra: object,
) -> RuntimeTargetComponents:
    """Construct the component bundle for the APTL target.

    ``provisioning-only`` declares only a Provisioner. Orchestrator,
    evaluator, and participant_runtime are absent at this profile tier
    and graduate in follow-on commits. Single source of truth — both
    :func:`create_aptl_target` and :func:`register` route through here.

    ``backend`` / ``profiles`` / ``build`` flow into the provisioner so
    callers (CLI, tests, advisory CI) control whether ``apply()`` drives
    real Docker or returns a not-wired diagnostic.
    """
    return RuntimeTargetComponents(
        provisioner=AptlProvisioner(
            backend=backend, profiles=profiles, build=build
        ),
        orchestrator=None,
        evaluator=None,
        participant_runtime=None,
    )


def create_aptl_target(
    *,
    version: str | None = None,
    backend: "DeploymentBackend | None" = None,
    profiles: tuple[str, ...] | list[str] = DEFAULT_PROFILES,
    build: bool = True,
) -> RuntimeTarget:
    """Return APTL as an ACES :class:`RuntimeTarget`.

    Pass ``backend=...`` (a configured :class:`DeploymentBackend`) to wire
    ``apply()`` through to the lab. Without it the target is
    conformance-only and ``apply()`` of an actionable plan returns a
    ``aptl.backend-not-wired`` diagnostic.
    """
    components = _build_components(
        backend=backend, profiles=profiles, build=build
    )
    return RuntimeTarget(
        name=BACKEND_NAME,
        manifest=create_aptl_manifest(version=version),
        provisioner=components.provisioner,
        orchestrator=components.orchestrator,
        evaluator=components.evaluator,
        participant_runtime=components.participant_runtime,
    )


def register(
    registry: BackendRegistry,
    *,
    version: str | None = None,
    backend: "DeploymentBackend | None" = None,
    profiles: tuple[str, ...] | list[str] = DEFAULT_PROFILES,
    build: bool = True,
) -> None:
    """Register APTL with an ACES :class:`BackendRegistry`.

    No auto-registration at import time — callers (CI, test harness,
    APTL's CLI at cutover) decide when to wire APTL into ACES. Backend
    + profiles + build flags closure into the components factory so the
    registry-driven path produces a fully-wired provisioner.
    """
    registry.register(
        BACKEND_NAME,
        manifest_factory=lambda **cfg: create_aptl_manifest(version=version),
        components_factory=lambda **cfg: _build_components(
            backend=backend, profiles=profiles, build=build, **cfg
        ),
    )
