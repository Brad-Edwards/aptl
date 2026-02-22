"""Tests for OCSF-aligned detection models and scoring.

Tests exercise SeverityId enum, ExpectedDetection/DetectionResult/DetectionCoverage
models, match_detection(), score_detection_coverage(), and format_detection_report().
"""

from types import SimpleNamespace

import pytest

from aptl.core.detection import (
    DetectionCoverage,
    DetectionResult,
    ExpectedDetection,
    SeverityId,
    format_detection_report,
    match_detection,
    score_detection_coverage,
)


# ---------------------------------------------------------------------------
# SeverityId enum
# ---------------------------------------------------------------------------


class TestSeverityId:
    """Tests for the OCSF SeverityId enum."""

    def test_values(self):
        assert SeverityId.UNKNOWN == 0
        assert SeverityId.INFO == 1
        assert SeverityId.LOW == 2
        assert SeverityId.MEDIUM == 3
        assert SeverityId.HIGH == 4
        assert SeverityId.CRITICAL == 5
        assert SeverityId.FATAL == 6

    def test_ordering(self):
        assert SeverityId.LOW < SeverityId.MEDIUM
        assert SeverityId.MEDIUM < SeverityId.HIGH
        assert SeverityId.HIGH < SeverityId.CRITICAL

    def test_is_int(self):
        assert isinstance(SeverityId.HIGH, int)
        assert SeverityId.HIGH + 1 == 5


# ---------------------------------------------------------------------------
# ExpectedDetection model
# ---------------------------------------------------------------------------


class TestExpectedDetection:
    """Tests for the OCSF ExpectedDetection model."""

    def test_minimal(self):
        det = ExpectedDetection(
            product_name="wazuh",
            severity_id=3,
            description="Test detection",
        )
        assert det.product_name == "wazuh"
        assert det.severity_id == SeverityId.MEDIUM
        assert det.analytic_uid is None
        assert det.analytic_name is None
        assert det.max_detection_time_seconds == 60

    def test_full(self):
        det = ExpectedDetection(
            product_name="suricata",
            analytic_uid="1000001",
            analytic_name="port_scan",
            severity_id=4,
            description="Port scan detected",
            max_detection_time_seconds=30,
        )
        assert det.analytic_uid == "1000001"
        assert det.analytic_name == "port_scan"
        assert det.severity_id == SeverityId.HIGH
        assert det.max_detection_time_seconds == 30


# ---------------------------------------------------------------------------
# DetectionResult model
# ---------------------------------------------------------------------------


class TestDetectionResult:
    """Tests for the DetectionResult model."""

    def test_detected(self):
        result = DetectionResult(
            step_number=1,
            technique_id="T1190",
            detected=True,
            severity_id=4,
            analytic_uid="302010",
            product_name="wazuh",
            detection_time_seconds=5.2,
        )
        assert result.detected is True
        assert result.severity_id == SeverityId.HIGH
        assert result.detection_time_seconds == 5.2

    def test_not_detected(self):
        result = DetectionResult(
            step_number=2,
            technique_id="T1059",
            detected=False,
        )
        assert result.detected is False
        assert result.severity_id is None
        assert result.detection_time_seconds is None


# ---------------------------------------------------------------------------
# DetectionCoverage model
# ---------------------------------------------------------------------------


class TestDetectionCoverage:
    """Tests for the DetectionCoverage model."""

    def test_full_coverage(self):
        cov = DetectionCoverage(
            scenario_id="test",
            total_steps=3,
            detected_steps=3,
            detection_coverage=1.0,
            results=[],
        )
        assert cov.detection_coverage == 1.0
        assert cov.gaps == []

    def test_partial_coverage(self):
        cov = DetectionCoverage(
            scenario_id="test",
            total_steps=4,
            detected_steps=2,
            detection_coverage=0.5,
            results=[],
            gaps=["T1190", "T1059"],
        )
        assert len(cov.gaps) == 2


# ---------------------------------------------------------------------------
# match_detection
# ---------------------------------------------------------------------------


class TestMatchDetection:
    """Tests for the match_detection() function."""

    def _expected(self, **kwargs):
        defaults = {
            "product_name": "wazuh",
            "severity_id": 3,
            "description": "test",
        }
        defaults.update(kwargs)
        return ExpectedDetection(**defaults)

    def test_product_name_match(self):
        expected = self._expected(product_name="wazuh")
        assert match_detection(expected, {"product_name": "wazuh", "severity_id": 3})

    def test_product_name_case_insensitive(self):
        expected = self._expected(product_name="Wazuh")
        assert match_detection(expected, {"product_name": "WAZUH", "severity_id": 3})

    def test_product_name_mismatch(self):
        expected = self._expected(product_name="wazuh")
        assert not match_detection(expected, {"product_name": "suricata", "severity_id": 3})

    def test_analytic_uid_exact_match(self):
        expected = self._expected(analytic_uid="302010")
        assert match_detection(expected, {
            "product_name": "wazuh",
            "analytic_uid": "302010",
            "severity_id": 3,
        })

    def test_analytic_uid_mismatch(self):
        expected = self._expected(analytic_uid="302010")
        assert not match_detection(expected, {
            "product_name": "wazuh",
            "analytic_uid": "999999",
            "severity_id": 3,
        })

    def test_analytic_name_substring(self):
        expected = self._expected(analytic_name="sqli")
        assert match_detection(expected, {
            "product_name": "wazuh",
            "analytic_name": "web_attack_sqli_detection",
            "severity_id": 3,
        })

    def test_analytic_name_case_insensitive(self):
        expected = self._expected(analytic_name="SQLi")
        assert match_detection(expected, {
            "product_name": "wazuh",
            "analytic_name": "Web_Attack_SQLI_Rule",
            "severity_id": 3,
        })

    def test_analytic_name_mismatch(self):
        expected = self._expected(analytic_name="sqli")
        assert not match_detection(expected, {
            "product_name": "wazuh",
            "analytic_name": "brute_force",
            "severity_id": 3,
        })

    def test_severity_threshold_met(self):
        expected = self._expected(severity_id=3)
        assert match_detection(expected, {"product_name": "wazuh", "severity_id": 4})

    def test_severity_threshold_exact(self):
        expected = self._expected(severity_id=3)
        assert match_detection(expected, {"product_name": "wazuh", "severity_id": 3})

    def test_severity_below_threshold(self):
        expected = self._expected(severity_id=4)
        assert not match_detection(expected, {"product_name": "wazuh", "severity_id": 2})

    def test_no_severity_in_alert_passes(self):
        expected = self._expected(severity_id=4)
        assert match_detection(expected, {"product_name": "wazuh"})


# ---------------------------------------------------------------------------
# score_detection_coverage
# ---------------------------------------------------------------------------


def _make_step(technique_id, technique_name="Step", tactic="Tactic"):
    return SimpleNamespace(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
    )


class TestScoreDetectionCoverage:
    """Tests for score_detection_coverage()."""

    def test_all_detected(self):
        steps = [_make_step("T1001"), _make_step("T1002")]
        results = [
            DetectionResult(step_number=1, technique_id="T1001", detected=True, detection_time_seconds=5.0),
            DetectionResult(step_number=2, technique_id="T1002", detected=True, detection_time_seconds=10.0),
        ]
        cov = score_detection_coverage("test", steps, results)
        assert cov.detected_steps == 2
        assert cov.total_steps == 2
        assert cov.detection_coverage == 1.0
        assert cov.avg_detection_time_seconds == 7.5
        assert cov.gaps == []

    def test_none_detected(self):
        steps = [_make_step("T1001"), _make_step("T1002")]
        results = [
            DetectionResult(step_number=1, technique_id="T1001", detected=False),
            DetectionResult(step_number=2, technique_id="T1002", detected=False),
        ]
        cov = score_detection_coverage("test", steps, results)
        assert cov.detected_steps == 0
        assert cov.detection_coverage == 0.0
        assert cov.avg_detection_time_seconds is None
        assert len(cov.gaps) == 2

    def test_partial_detection(self):
        steps = [_make_step("T1001"), _make_step("T1002")]
        results = [
            DetectionResult(step_number=1, technique_id="T1001", detected=True, detection_time_seconds=3.0),
            DetectionResult(step_number=2, technique_id="T1002", detected=False),
        ]
        cov = score_detection_coverage("test", steps, results)
        assert cov.detected_steps == 1
        assert cov.detection_coverage == 0.5
        assert cov.avg_detection_time_seconds == 3.0
        assert cov.gaps == ["T1002"]
        assert cov.mitre_coverage["T1001"] is True
        assert cov.mitre_coverage["T1002"] is False

    def test_empty_steps(self):
        cov = score_detection_coverage("test", [], [])
        assert cov.total_steps == 0
        assert cov.detection_coverage == 0.0


# ---------------------------------------------------------------------------
# format_detection_report
# ---------------------------------------------------------------------------


class TestFormatDetectionReport:
    """Tests for format_detection_report()."""

    def test_report_contains_scenario_info(self):
        steps = [
            _make_step("T1001", "Active Scanning", "Reconnaissance"),
            _make_step("T1002", "Exploit App", "Initial Access"),
        ]
        results = [
            DetectionResult(step_number=1, technique_id="T1001", detected=True, detection_time_seconds=5.0),
            DetectionResult(step_number=2, technique_id="T1002", detected=False),
        ]
        cov = score_detection_coverage("test", steps, results)
        report = format_detection_report(
            "Test Playbook", "intermediate", "Recon -> Exploit", steps, cov,
        )

        assert "Test Playbook" in report
        assert "intermediate" in report
        assert "Recon -> Exploit" in report
        assert "1/2" in report
        assert "DETECTED" in report
        assert "MISSED" in report
        assert "Detection Gaps" in report
        assert "T1002" in report
        assert "MITRE ATT&CK Coverage" in report

    def test_report_all_detected_no_gaps(self):
        steps = [_make_step("T1001", "Scan", "Recon")]
        results = [
            DetectionResult(step_number=1, technique_id="T1001", detected=True, detection_time_seconds=5.0),
        ]
        cov = score_detection_coverage("test", steps, results)
        report = format_detection_report("Test", "beginner", "Scan", steps, cov)

        assert "1/1" in report
        assert "Detection Gaps" not in report
        assert "Avg Detection Time" in report
