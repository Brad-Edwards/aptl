"""ACES backend adapter conformance tests (Phase A.1 / #310).

Pins the contract surface between APTL's `aptl.backends.aces` adapter and
the ACES `provisioning-only` profile. The adapter is a skeleton at this
stage — `apply()` raises NotImplementedError for non-empty plans — so the
tests assert shape conformance, not full lab orchestration. Real apply()
wiring lands in a later Phase A PR.
"""

from __future__ import annotations

import pytest

# Skip the entire module when aces-sdl is not installed; CI installs it via
# pip's git+ pinned dependency. Local dev without that pin still passes the
# rest of the suite.
aces_protocols = pytest.importorskip("aces_backend_protocols.protocols")
aces_capabilities = pytest.importorskip("aces_backend_protocols.capabilities")
aces_registry = pytest.importorskip("aces_processor.registry")
aces_conformance = pytest.importorskip("aces_conformance.conformance")
aces_models = pytest.importorskip("aces_processor.models")

from aces_backend_protocols.capabilities import BackendManifest, ProvisionerCapabilities
from aces_conformance.conformance import run_target_conformance
from aces_processor.models import ProvisioningPlan, RuntimeSnapshot
from aces_processor.registry import BackendRegistry, RuntimeTarget


def test_create_aptl_manifest_declares_provisioning_only_profile() -> None:
    """Manifest declares `provisioning-only` (no orchestrator/evaluator)."""
    from aptl.backends.aces import create_aptl_manifest

    manifest = create_aptl_manifest()

    assert isinstance(manifest, BackendManifest)
    assert isinstance(manifest.capabilities.provisioner, ProvisionerCapabilities)
    # provisioning-only profile: no orchestrator, no evaluator, no participant runtime
    assert manifest.capabilities.orchestrator is None
    assert manifest.capabilities.evaluator is None
    assert manifest.capabilities.participant_runtime is None
    # Required contracts for provisioning-only per
    # contracts/profiles/backend/provisioning-only.json
    required_contracts = {
        "backend-manifest-v2",
        "operation-receipt-v1",
        "operation-status-v1",
        "runtime-snapshot-v1",
    }
    assert required_contracts.issubset(manifest.supported_contract_versions)
    # APTL identity
    assert manifest.identity.name == "aptl"
    # Compatible processor matches ACES's published reference identity
    # (codex pre-push cycle 1 #310) — sourced from aces_processor.manifest
    # so a rename surfaces as ImportError, not a silent identity mismatch.
    from aces_processor.manifest import REFERENCE_PROCESSOR_NAME
    assert REFERENCE_PROCESSOR_NAME in manifest.compatibility.processors
    # Capability values themselves — without these explicit assertions a
    # regression that dropped `switch` (silently breaking networked plans)
    # or `linux` (silently breaking the entire APTL lab) would not fail
    # this test. Test-quality review cycle 1 T-001 (#310).
    provisioner = manifest.capabilities.provisioner
    assert provisioner.supported_node_types == frozenset({"vm", "switch"})
    assert provisioner.supported_os_families == frozenset({"linux", "windows"})
    assert provisioner.supported_content_types == frozenset({"file"})
    assert provisioner.supported_account_features == frozenset({"shell"})
    assert provisioner.supports_acls is False
    assert provisioner.supports_accounts is True


def test_provisioner_validate_returns_empty_diagnostics_for_empty_plan() -> None:
    """Skeleton validate() emits no diagnostics for an empty plan.

    Non-empty plans are surfaced via apply()'s NotImplementedError, not
    validate's warnings — the next test pins that contract too so a
    Phase A.2 regression that accidentally raises from validate() shows
    up immediately.
    """
    from aptl.backends.aces import AptlProvisioner

    provisioner = AptlProvisioner()
    plan = ProvisioningPlan()  # canonical empty: list[]/dict{} via factories

    diagnostics = provisioner.validate(plan)

    assert diagnostics == []


def test_provisioner_validate_returns_empty_diagnostics_for_non_empty_plan() -> None:
    """Skeleton validate() is non-raising and side-effect-free regardless
    of plan content — even for actionable operations whose apply() path
    will later raise. Phase A.2 adds capability inspection here; this
    test pins the baseline so an accidental raise from validate() during
    Phase A.2 implementation surfaces as a regression. Test-quality
    review cycle 1 T-004 (#310)."""
    from aces_processor.models import ChangeAction, ProvisionOp
    from aptl.backends.aces import AptlProvisioner

    provisioner = AptlProvisioner()
    plan = ProvisioningPlan(
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address="node/aptl-victim",
                resource_type="node",
                payload={},
            ),
        ],
    )

    diagnostics = provisioner.validate(plan)

    assert diagnostics == []


def test_provisioner_apply_returns_success_for_empty_plan() -> None:
    """Empty-operation plan applies as success (no-op).

    This is the shape conformance — Phase A.1 stops here. Phase A.2 wires
    real apply() against aptl.core.lab.orchestrate_lab_start.
    """
    from aptl.backends.aces import AptlProvisioner

    provisioner = AptlProvisioner()
    plan = ProvisioningPlan()
    snapshot = RuntimeSnapshot()

    result = provisioner.apply(plan, snapshot)

    assert result.success is True
    # Empty plan: no changes recorded; snapshot returned unchanged.
    assert result.snapshot is snapshot
    assert result.changed_addresses == []


def test_provisioner_apply_succeeds_for_unchanged_only_plan() -> None:
    """A plan whose operations are all ``ChangeAction.UNCHANGED`` is
    what the control plane emits during idempotent re-applies. The
    adapter MUST accept these as no-op success, not raise — otherwise
    repeated apply cycles break once the snapshot already matches the
    plan. Codex pre-push cycle 1 (#310)."""
    from aces_processor.models import ChangeAction, ProvisionOp
    from aptl.backends.aces import AptlProvisioner

    provisioner = AptlProvisioner()
    plan = ProvisioningPlan(
        operations=[
            ProvisionOp(
                action=ChangeAction.UNCHANGED,
                address="node/aptl-victim",
                resource_type="node",
                payload={},
            ),
        ],
    )
    snapshot = RuntimeSnapshot()

    result = provisioner.apply(plan, snapshot)

    assert result.success is True
    assert result.snapshot is snapshot


def test_provisioner_apply_returns_diagnostic_when_no_backend_wired() -> None:
    """With no DeploymentBackend wired, an actionable plan does NOT
    raise — it returns ``ApplyResult(success=False, diagnostics=[...])``
    with code ``aptl.backend-not-wired``. ACES's idiom is that backend
    errors flow as diagnostics on the result, never as exceptions out
    of apply(). ADR-035 user-visible-invariance contract."""
    from aces_processor.models import ChangeAction, ProvisionOp
    from aptl.backends.aces import AptlProvisioner

    provisioner = AptlProvisioner()
    plan = ProvisioningPlan(
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address="node/aptl-victim",
                resource_type="node",
                payload={},
            ),
        ],
    )
    snapshot = RuntimeSnapshot()

    result = provisioner.apply(plan, snapshot)

    assert result.success is False
    assert len(result.diagnostics) == 1
    diag = result.diagnostics[0]
    assert diag.code == "aptl.backend-not-wired"
    assert diag.address == "runtime.apply.provisioning"


def test_provisioner_apply_drives_backend_start_for_actionable_plan() -> None:
    """With a backend wired, apply() calls backend.start() with the
    configured profiles and returns ApplyResult(success=True) when the
    LabResult is successful. changed_addresses lists the addresses of
    every actionable operation in the plan."""
    from unittest.mock import MagicMock

    from aces_processor.models import ChangeAction, ProvisionOp
    from aptl.backends.aces import AptlProvisioner
    from aptl.core.lab_types import LabResult, StartupOutcome

    backend = MagicMock()
    backend.start.return_value = LabResult(
        success=True, message="ok", outcome=StartupOutcome.READY
    )
    provisioner = AptlProvisioner(
        backend=backend, profiles=["wazuh", "kali"], build=False
    )
    plan = ProvisioningPlan(
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address="provision.node.victim",
                resource_type="node",
                payload={},
            ),
        ],
    )
    snapshot = RuntimeSnapshot()

    result = provisioner.apply(plan, snapshot)

    assert result.success is True
    assert result.changed_addresses == ["provision.node.victim"]
    backend.start.assert_called_once_with(["wazuh", "kali"], build=False)


def test_provisioner_apply_surfaces_backend_failure_as_diagnostic() -> None:
    """When backend.start() returns LabResult(success=False), apply()
    returns ApplyResult(success=False) with a structured diagnostic
    carrying APTL's error code namespace. Lab failure messages flow
    through to ACES diagnostics without losing semantics."""
    from unittest.mock import MagicMock

    from aces_processor.models import ChangeAction, ProvisionOp
    from aptl.backends.aces import AptlProvisioner
    from aptl.core.lab_types import LabResult, StartupOutcome

    backend = MagicMock()
    backend.start.return_value = LabResult(
        success=False,
        error="container 'wazuh-manager' refused to start",
        outcome=StartupOutcome.FAILED,
    )
    provisioner = AptlProvisioner(backend=backend)
    plan = ProvisioningPlan(
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address="provision.node.victim",
                resource_type="node",
                payload={},
            ),
        ],
    )

    result = provisioner.apply(plan, RuntimeSnapshot())

    assert result.success is False
    assert len(result.diagnostics) == 1
    diag = result.diagnostics[0]
    assert diag.code == "aptl.lab-start-failed"
    assert "wazuh-manager" in diag.message


def test_create_aptl_target_returns_runtime_target_with_provisioner() -> None:
    """Factory produces a RuntimeTarget wired to AptlProvisioner.

    The concrete-class check (rather than just duck-typing) catches a
    regression that swaps in a stub or unrelated provisioner from a
    different package while still satisfying the Provisioner Protocol
    shape. Test-quality review cycle 1 T-003 (#310).
    """
    from aptl.backends.aces import AptlProvisioner, create_aptl_target

    target = create_aptl_target()

    assert isinstance(target, RuntimeTarget)
    # Concrete-class wiring — duck-typing isn't enough here because any
    # object with `validate` and `apply` methods would pass, including
    # accidentally-wired stubs.
    assert isinstance(target.provisioner, AptlProvisioner)
    # provisioning-only: no orchestrator/evaluator/participant runtime
    assert target.orchestrator is None
    assert target.evaluator is None
    assert target.participant_runtime is None
    assert target.name == "aptl"


def test_register_adds_backend_to_aces_registry() -> None:
    """register(registry) wires APTL into a fresh BackendRegistry."""
    from aptl.backends.aces import register

    registry = BackendRegistry()
    register(registry)

    assert registry.is_registered("aptl")


def test_register_is_idempotent_against_external_registry() -> None:
    """Calling register on an already-registered registry raises rather
    than silently overwriting — matches ACES BackendRegistry.register()
    contract. Caller controls when to register."""
    from aptl.backends.aces import register

    registry = BackendRegistry()
    register(registry)

    with pytest.raises(ValueError, match="already registered"):
        register(registry)


def test_aces_conformance_provisioning_only_passes_for_aptl_target() -> None:
    """The ACES conformance suite accepts the APTL target for the
    provisioning-only profile. This is the gate that #310 Phase A wires
    as advisory CI."""
    from aptl.backends.aces import create_aptl_target

    target = create_aptl_target()

    report = run_target_conformance(target, profile="provisioning-only")

    # Fatal diagnostics fail the gate; advisory-status entries are fine.
    fatal_codes = {
        "conformance.profile-load-failed",
        "conformance.profile-runtime-surface-unknown",
    }
    fatal = [d for d in report.diagnostics if d.code in fatal_codes]
    assert not fatal, f"Fatal conformance diagnostics: {fatal}"
    # The report should pass overall — provisioning-only requires only the
    # Provisioner role, which the skeleton implements shape-correctly.
    assert report.passed, (
        f"Conformance report failed; diagnostics: {report.diagnostics}"
    )
