"""Tests for the REP-003 detection-content provenance provider (issue #452).

The behavior this replaces (``snapshot.detection_content_digest``) hashed an
unframed concatenation over four non-recursive globs, two of which
(``config/wazuh/etc/rules``, ``config/wazuh/etc/decoders``) do not exist in
this repository at all — the real Wazuh rule/decoder surface is
``config/wazuh_cluster`` and Suricata's MISP content is nested under
``config/suricata/rules/misp``. These tests pin the corrected surface, the
per-leaf framing, and the safe reading path.
"""

import os

import pytest

from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext
from aptl.core.provenance.providers.detection import (
    DETECTION_PROVIDER_ID,
    DETECTION_ROOTS,
    DetectionContentProvider,
)
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    SealPoint,
)


def _context(*, max_bytes=65536, max_entries=64, timeout_s=30, clock=None):
    registration = ProvenanceProviderRegistration(
        provider_id=DETECTION_PROVIDER_ID,
        implementation_version="1.0.0",
        provenance_kind="detection-content",
        owner_adapter="aptl.core.provenance.providers.detection",
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key="detection-content-required",
        limits=ProvenanceLimits(
            max_bytes=max_bytes, max_entries=max_entries, timeout_s=timeout_s
        ),
    )
    ticker = clock or (lambda: 0.0)
    return ProvenanceContext(registration=registration, clock=ticker, started_at=0.0)


def _write(root, relative, content=b"rule"):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def _leaf_ids(result):
    return {leaf.logical_id for leaf in result.leaves}


class TestSurfaceCoverage:
    """The corrected surface covers what the previous globs missed."""

    def test_nested_suricata_misp_content_is_covered(self, tmp_path):
        """The old non-recursive glob missed config/suricata/rules/misp/."""
        _write(tmp_path, "config/suricata/rules/misp/misp-iocs.rules")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert result.status is ProvenanceStatus.COLLECTED
        assert any("misp-iocs.rules" in name for name in _leaf_ids(result))

    def test_wazuh_cluster_rules_and_decoders_are_covered(self, tmp_path):
        """The old globs pointed at config/wazuh/etc/, which does not exist."""
        _write(tmp_path, "config/wazuh_cluster/suricata_rules.xml")
        _write(tmp_path, "config/wazuh_cluster/samba_decoders.xml")
        result = DetectionContentProvider(tmp_path).collect(_context())
        names = _leaf_ids(result)
        assert any("suricata_rules.xml" in name for name in names)
        assert any("samba_decoders.xml" in name for name in names)

    def test_allowlists_are_covered(self, tmp_path):
        _write(tmp_path, "config/wazuh_cluster/etc/lists/active-response-whitelist")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert any("active-response-whitelist" in name for name in _leaf_ids(result))

    def test_top_level_suricata_rules_are_still_covered(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/local.rules")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert any("local.rules" in name for name in _leaf_ids(result))

    def test_unrelated_files_are_not_ingested(self, tmp_path):
        """Roots carry explicit suffix allowlists; a script is not detection content."""
        _write(tmp_path, "config/wazuh_cluster/patch-rule-path.py", b"import os")
        _write(tmp_path, "config/wazuh_cluster/suricata_rules.xml")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert not any("patch-rule-path" in name for name in _leaf_ids(result))

    def test_every_declared_root_is_under_config(self, tmp_path):
        """No root may reach outside the project's detection content."""
        for root in DETECTION_ROOTS:
            assert root.relative_root.startswith("config/")
            assert ".." not in root.relative_root


class TestTargetedDifferences:
    """Changing one artifact moves its own leaf and the family, nothing else."""

    def test_changing_one_rule_changes_only_its_leaf(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/local.rules", b"v1")
        _write(tmp_path, "config/wazuh_cluster/suricata_rules.xml", b"stable")
        before = DetectionContentProvider(tmp_path).collect(_context())

        _write(tmp_path, "config/suricata/rules/local.rules", b"v2")
        after = DetectionContentProvider(tmp_path).collect(_context())

        before_by_id = {leaf.logical_id: leaf.digest for leaf in before.leaves}
        after_by_id = {leaf.logical_id: leaf.digest for leaf in after.leaves}
        changed = [
            name for name in before_by_id if before_by_id[name] != after_by_id.get(name)
        ]
        assert len(changed) == 1
        assert "local.rules" in changed[0]

    def test_identical_content_is_stable_across_collections(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/local.rules", b"v1")
        first = DetectionContentProvider(tmp_path).collect(_context())
        second = DetectionContentProvider(tmp_path).collect(_context())
        assert first.leaves == second.leaves

    def test_content_split_across_files_is_not_ambiguous(self, tmp_path):
        """The concatenation collision the previous implementation had."""
        _write(tmp_path, "config/suricata/rules/a.rules", b"ab")
        _write(tmp_path, "config/suricata/rules/b.rules", b"c")
        first = DetectionContentProvider(tmp_path).collect(_context())

        _write(tmp_path, "config/suricata/rules/a.rules", b"a")
        _write(tmp_path, "config/suricata/rules/b.rules", b"bc")
        second = DetectionContentProvider(tmp_path).collect(_context())
        assert first.leaves != second.leaves

    def test_leaves_are_sorted_regardless_of_filesystem_order(self, tmp_path):
        for name in ("z.rules", "a.rules", "m.rules"):
            _write(tmp_path, f"config/suricata/rules/{name}")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert list(result.leaves) == sorted(result.leaves)


class TestAbsentAndDegradedSources:
    """Absence and degradation are explicit, never an empty success."""

    def test_no_detection_content_is_unavailable_not_empty_success(self, tmp_path):
        """The previous helper returned '' here, which read as 'nothing changed'."""
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert result.status is ProvenanceStatus.UNAVAILABLE
        assert result.leaves == ()

    def test_exceeding_the_entry_limit_is_truncated(self, tmp_path):
        for index in range(6):
            _write(tmp_path, f"config/suricata/rules/rule-{index}.rules")
        result = DetectionContentProvider(tmp_path).collect(_context(max_entries=3))
        assert result.status is ProvenanceStatus.TRUNCATED

    def test_exceeding_the_byte_limit_is_truncated(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/big.rules", b"x" * 4096)
        result = DetectionContentProvider(tmp_path).collect(_context(max_bytes=1024))
        assert result.status is ProvenanceStatus.TRUNCATED

    def test_a_truncated_collection_reports_no_partial_content_as_complete(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/big.rules", b"x" * 4096)
        result = DetectionContentProvider(tmp_path).collect(_context(max_bytes=1024))
        assert result.status is not ProvenanceStatus.COLLECTED

    def test_expired_deadline_is_timed_out(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/local.rules")
        # The provider checks its deadline before each artifact, so a clock
        # already past the budget must stop it before the first read.
        result = DetectionContentProvider(tmp_path).collect(
            _context(timeout_s=5, clock=lambda: 99.0)
        )
        assert result.status is ProvenanceStatus.TIMED_OUT
        assert result.leaves == ()

    def test_unreadable_root_is_denied_not_silently_skipped(self, tmp_path):
        rules = tmp_path / "config" / "suricata" / "rules"
        rules.mkdir(parents=True)
        (rules / "local.rules").write_bytes(b"rule")
        os.chmod(rules, 0o000)
        try:
            result = DetectionContentProvider(tmp_path).collect(_context())
            assert result.status in {ProvenanceStatus.DENIED, ProvenanceStatus.COLLECTED}
            if result.status is ProvenanceStatus.DENIED:
                assert result.leaves == ()
        finally:
            os.chmod(rules, 0o755)


class TestSafeReading:
    """Reading is path-contained and no-follow; hostile entries never ingest."""

    def test_a_symlinked_rule_file_is_not_followed(self, tmp_path):
        secret = tmp_path / "outside-secret.txt"
        secret.write_bytes(b"SECRET-CONTENT")
        rules = tmp_path / "config" / "suricata" / "rules"
        rules.mkdir(parents=True)
        os.symlink(secret, rules / "link.rules")
        _write(tmp_path, "config/suricata/rules/real.rules", b"rule")

        result = DetectionContentProvider(tmp_path).collect(_context())
        assert not any("link.rules" in name for name in _leaf_ids(result))
        assert "SECRET-CONTENT" not in repr(result.payload)

    def test_a_symlinked_root_directory_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.rules").write_bytes(b"SECRET-CONTENT")
        suricata = tmp_path / "config" / "suricata"
        suricata.mkdir(parents=True)
        os.symlink(outside, suricata / "rules")

        result = DetectionContentProvider(tmp_path).collect(_context())
        assert not any("evil.rules" in name for name in _leaf_ids(result))

    def test_a_special_file_is_not_ingested(self, tmp_path):
        rules = tmp_path / "config" / "suricata" / "rules"
        rules.mkdir(parents=True)
        os.mkfifo(rules / "pipe.rules")
        _write(tmp_path, "config/suricata/rules/real.rules")

        result = DetectionContentProvider(tmp_path).collect(_context())
        assert not any("pipe.rules" in name for name in _leaf_ids(result))

    def test_env_is_never_read_even_if_placed_under_a_root(self, tmp_path):
        """Secret sources are excluded by suffix allowlist, not by later scrubbing."""
        _write(tmp_path, "config/suricata/rules/.env", b"WAZUH_PASSWORD=hunter2")
        _write(tmp_path, "config/suricata/rules/real.rules")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert not any(".env" in name for name in _leaf_ids(result))
        assert "hunter2" not in repr(result)

    def test_payload_carries_counts_and_root_ids_only(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/local.rules")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert set(result.payload) == {"roots", "artifact_count"}
        assert isinstance(result.payload["artifact_count"], int)

    def test_no_host_path_appears_in_the_result(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/local.rules")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert str(tmp_path) not in repr(result)

    def test_logical_ids_are_project_relative(self, tmp_path):
        _write(tmp_path, "config/suricata/rules/local.rules")
        result = DetectionContentProvider(tmp_path).collect(_context())
        for name in _leaf_ids(result):
            assert not name.startswith("/")
            assert ".." not in name


@pytest.mark.fuzz
class TestDetectionFuzz:
    """Property-based coverage for hostile names and sizes."""

    @pytest.mark.parametrize(
        "name",
        [
            "a" * 200 + ".rules",
            "weird name.rules",
            "nested/deep/deeper/file.rules",
            ".hidden.rules",
        ],
    )
    def test_unusual_names_never_raise(self, tmp_path, name):
        _write(tmp_path, f"config/suricata/rules/{name}")
        result = DetectionContentProvider(tmp_path).collect(_context())
        assert result.status in set(ProvenanceStatus)
