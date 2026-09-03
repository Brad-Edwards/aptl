"""Tests for the REP-003 provenance outcome vocabulary (issue #452).

Covers the preflight rule that missing, denied, unsupported, truncated,
timed-out and failed sources are EXPLICIT results — never empty strings,
empty maps, absent keys, or a fabricated digest.
"""

import pytest

from aptl.core.provenance.outcomes import (
    SUCCESS_STATUSES,
    ProvenanceLimitation,
    ProvenanceOutcomeError,
    ProvenanceStatus,
    limitation_for,
    reason_code_for,
)


class TestStatusVocabulary:
    """The status set is closed and covers every REP-003 failure mode."""

    def test_every_required_status_exists(self):
        assert {status.value for status in ProvenanceStatus} == {
            "collected",
            "unavailable",
            "denied",
            "unsupported",
            "timed-out",
            "truncated",
            "failed",
        }

    def test_only_collected_is_a_full_success(self):
        assert SUCCESS_STATUSES == frozenset({ProvenanceStatus.COLLECTED})

    def test_truncated_is_not_a_success(self):
        """Truncation is disclosed degradation, never silent success."""
        assert ProvenanceStatus.TRUNCATED not in SUCCESS_STATUSES

    def test_every_non_success_status_has_a_stable_reason_code(self):
        for status in ProvenanceStatus:
            if status in SUCCESS_STATUSES:
                continue
            code = reason_code_for(status)
            assert code.startswith("aptl.run-provenance.")
            assert code == reason_code_for(status), "reason codes must be stable"

    def test_collected_has_no_reason_code(self):
        with pytest.raises(ProvenanceOutcomeError):
            reason_code_for(ProvenanceStatus.COLLECTED)


class TestLimitation:
    """A limitation carries stable codes and safe counters only."""

    def test_limitation_records_provider_status_and_code(self):
        limitation = limitation_for("detection-content", ProvenanceStatus.DENIED)
        assert limitation.provider_id == "detection-content"
        assert limitation.status is ProvenanceStatus.DENIED
        assert limitation.reason_code == reason_code_for(ProvenanceStatus.DENIED)

    def test_limitation_projection_is_bounded_and_safe(self):
        limitation = limitation_for("detection-content", ProvenanceStatus.TIMED_OUT)
        projection = limitation.projection()
        assert set(projection) == {"provider_id", "status", "reason_code", "detail"}
        assert all(isinstance(value, str) for value in projection.values())

    def test_detail_is_a_fixed_safe_message_not_an_exception_string(self):
        """`str(exc)` must never become a record field."""
        limitation = limitation_for(
            "detection-content",
            ProvenanceStatus.FAILED,
            detail="ValueError: /home/secret/path leaked token=abc123",
        )
        assert "secret" not in limitation.projection()["detail"]
        assert "abc123" not in limitation.projection()["detail"]

    def test_known_safe_detail_is_preserved(self):
        limitation = limitation_for(
            "detection-content", ProvenanceStatus.TRUNCATED, detail="entry limit reached"
        )
        assert limitation.projection()["detail"] == "entry limit reached"

    def test_collected_cannot_produce_a_limitation(self):
        """A successful source has nothing to declare."""
        with pytest.raises(ProvenanceOutcomeError):
            limitation_for("detection-content", ProvenanceStatus.COLLECTED)

    @pytest.mark.parametrize("provider_id", ["", "bad id", "x" * 65, "a\x00b"])
    def test_hostile_provider_id_is_rejected(self, provider_id):
        with pytest.raises(ProvenanceOutcomeError):
            limitation_for(provider_id, ProvenanceStatus.DENIED)

    def test_limitations_sort_deterministically(self):
        first = limitation_for("apparatus", ProvenanceStatus.DENIED)
        second = limitation_for("detection-content", ProvenanceStatus.DENIED)
        assert sorted([second, first]) == [first, second]

    def test_limitation_is_immutable(self):
        limitation = ProvenanceLimitation(
            provider_id="apparatus",
            status=ProvenanceStatus.DENIED,
            reason_code=reason_code_for(ProvenanceStatus.DENIED),
            detail="",
        )
        with pytest.raises(AttributeError):
            limitation.provider_id = "other"  # type: ignore[misc]
