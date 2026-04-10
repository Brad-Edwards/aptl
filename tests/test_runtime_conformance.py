"""Backend conformance tests."""

from __future__ import annotations

from aptl.backends.stubs import create_stub_target
from aptl.core.runtime.conformance import (
    BackendCapabilityProfile,
    profile_for_manifest,
    required_contracts,
    run_fixture_suite,
    run_target_conformance,
)


def test_fixture_suite_passes_for_orchestration_evaluation_profile():
    report = run_fixture_suite(
        profile=BackendCapabilityProfile.ORCHESTRATION_EVALUATION
    )

    assert report.passed is True
    assert report.cases
    assert not report.diagnostics
    assert required_contracts(report.profile)


def test_target_conformance_passes_for_stub_target():
    report = run_target_conformance(create_stub_target())

    assert report.profile == BackendCapabilityProfile.ORCHESTRATION_EVALUATION
    assert report.passed is True
    assert not report.unsupported_capability_gaps


def test_profile_is_inferred_from_manifest_shape():
    target = create_stub_target()

    assert (
        profile_for_manifest(target.manifest)
        == BackendCapabilityProfile.ORCHESTRATION_EVALUATION
    )
