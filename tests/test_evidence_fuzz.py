"""Property-based tests for evidence acquisition (EXP-010 / issue #752 PR 2).

Run with ``pytest -m fuzz`` (skipped by the default run). Covers the streaming
byte-quota invariant and evidence-record identity determinism.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aptl.core.evidence.content_store import create_content_addressed
from aptl.core.evidence.records import derive_evidence_record_id
from aptl.core.experiment.capture_registry import CaptureBinding, CaptureLimits, CaptureVisibility
from aptl.core.runstore import LocalRunStore


def _binding() -> CaptureBinding:
    return CaptureBinding(
        capture_spec_id="cap-1", requirement_id="req-a", window_refs=("run-window",),
        registration_id="aptl.collector.a", implementation_version="1.0.0",
        contract_version="experiment-capture-spec/v1", effective_config_digest="sha256:" + "cd" * 32,
        channel_ref_id="chan", channel_ref_version="1.0.0", channel_kind="evaluation-history",
        capture_kind="trace", capture_scope="network", expected_media_types=("application/json",),
        required_artifact_roles=("observation",), sensitivity="internal", redaction_required=False,
        integrity_requirements=("sha256-digest",), retention_policy="retain", loss_disclosure_required=True,
        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
        limits=CaptureLimits(max_bytes=1024, max_artifact_count=10, max_duration_s=60),
    )


@pytest.mark.fuzz
class TestQuotaInvariant:
    @given(
        chunks=st.lists(st.binary(min_size=0, max_size=64), min_size=0, max_size=32),
        max_bytes=st.integers(min_value=1, max_value=512),
    )
    @settings(max_examples=120, deadline=2000)
    def test_stored_size_and_truncation_are_correct(self, tmp_path_factory, chunks, max_bytes):
        store = LocalRunStore(tmp_path_factory.mktemp("runs"))
        total = sum(len(c) for c in chunks)
        result = create_content_addressed(store, "run-1", chunks, subdir="evidence", max_bytes=max_bytes)
        assert result.size == min(total, max_bytes)
        assert result.truncated == (total > max_bytes)


@pytest.mark.fuzz
class TestRecordIdentity:
    @given(
        run_id=st.text(alphabet="abcdef0123456789-", min_size=1, max_size=16),
        content_digest=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
    )
    @settings(max_examples=80, deadline=2000)
    def test_identity_is_deterministic_and_content_sensitive(self, run_id, content_digest):
        binding = _binding()
        digest = f"sha256:{content_digest}"
        a = derive_evidence_record_id(run_id=run_id, planned_trial_id="t", binding=binding, content_digest=digest)
        b = derive_evidence_record_id(run_id=run_id, planned_trial_id="t", binding=binding, content_digest=digest)
        assert a == b
        assert a.startswith("evidence-")
        other = derive_evidence_record_id(
            run_id=run_id, planned_trial_id="t", binding=binding, content_digest="sha256:" + "0" * 64
        )
        if digest != "sha256:" + "0" * 64:
            assert a != other
