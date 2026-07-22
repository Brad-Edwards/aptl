"""Tests for the evidence collector adapters (EXP-010 / issue #752 PR 2).

Covers the generic windowed-query collector, the concrete built-in sources
(each distinguishing a source failure from legitimate emptiness at the owner
level — never the empty-on-error collapse), and the trusted wiring seam.
"""

from __future__ import annotations

import types

import pytest

from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.evidence.adapters.builtins import ContainerLogSource, RunArchiveSource, soc_windowed_source
from aptl.core.evidence.adapters.sources import SourceResult, WindowedQueryCollector
from aptl.core.evidence.adapters.wiring import BUILTIN_REGISTRATION_IDS, build_collectors
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.evidence.protocol import CollectorContext
from aptl.core.experiment.capture_registry import CaptureBinding, CaptureLimits, CaptureVisibility
from aptl.core.runstore import LocalRunStore

_CLOCK = FixedClockProvider(measurement_time="2026-07-20T00:00:00Z")


def _binding(registration_id="aptl.collector.mcp-red") -> CaptureBinding:
    return CaptureBinding(
        capture_spec_id="cap-1", requirement_id="req-a", window_refs=("run-window",),
        registration_id=registration_id, implementation_version="1.0.0",
        contract_version="experiment-capture-spec/v1", effective_config_digest="sha256:" + "cd" * 32,
        channel_ref_id="chan", channel_ref_version="1.0.0", channel_kind="participant-observation",
        capture_kind="observation", capture_scope="participant", expected_media_types=("application/json",),
        required_artifact_roles=("observation",), sensitivity="internal", redaction_required=False,
        integrity_requirements=("sha256-digest",), retention_policy="retain", loss_disclosure_required=True,
        visibility_class=CaptureVisibility.PARTICIPANT_VISIBLE,
        limits=CaptureLimits(max_bytes=4096, max_artifact_count=10, max_duration_s=60),
    )


def _context(registration_id="aptl.collector.mcp-red") -> CollectorContext:
    return CollectorContext(
        planned_trial_id="trial-1", run_id="run-1", attempt_id="attempt-1",
        binding=_binding(registration_id), deadline_seconds=60.0, clock=_CLOCK,
    )


class _FakeSource:
    def __init__(self, result: SourceResult) -> None:
        self._result = result

    def fetch(self, start_iso, end_iso) -> SourceResult:
        return self._result


class TestWindowedQueryCollector:
    def test_records_map_to_ok_with_json_bytes(self):
        source = _FakeSource(SourceResult(status=CollectorStatus.OK, records=[{"a": 1}, {"a": 2}]))
        collector = WindowedQueryCollector("aptl.collector.mcp-red", source)
        outcome = collector.stop(collector.start(_context()))
        assert outcome.status is CollectorStatus.OK
        assert outcome.event_count == 2
        assert outcome.media_type == "application/json"
        assert b'"a":1' in b"".join(outcome.chunks)

    def test_empty_records_are_empty_ok(self):
        source = _FakeSource(SourceResult(status=CollectorStatus.EMPTY_OK, records=[]))
        collector = WindowedQueryCollector("aptl.collector.mcp-red", source)
        outcome = collector.stop(collector.start(_context()))
        assert outcome.status is CollectorStatus.EMPTY_OK

    def test_source_failure_passes_through_without_chunks(self):
        source = _FakeSource(SourceResult(status=CollectorStatus.SOURCE_UNAVAILABLE))
        collector = WindowedQueryCollector("aptl.collector.mcp-red", source)
        outcome = collector.stop(collector.start(_context()))
        assert outcome.status is CollectorStatus.SOURCE_UNAVAILABLE
        assert not outcome.chunks


class TestRunArchiveSource:
    def test_missing_subtree_is_source_unavailable(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("run-1")
        source = RunArchiveSource(store, "run-1", "mcp-side")
        assert source.fetch("s", "e").status is CollectorStatus.SOURCE_UNAVAILABLE

    def test_present_but_empty_is_empty_ok(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.write_file("run-1", "mcp-side/tool-calls.jsonl", b"")
        source = RunArchiveSource(store, "run-1", "mcp-side")
        assert source.fetch("s", "e").status is CollectorStatus.EMPTY_OK

    def test_records_are_read_and_malformed_lines_dropped(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.write_file("run-1", "mcp-side/tool-calls.jsonl", b'{"a": 1}\nnot-json\n{"a": 2}\n')
        source = RunArchiveSource(store, "run-1", "mcp-side")
        result = source.fetch("s", "e")
        assert result.status is CollectorStatus.OK
        assert len(result.records) == 2
        assert result.dropped_count == 1


class TestContainerLogSource:
    def test_nonzero_returncode_is_source_unavailable(self):
        backend = types.SimpleNamespace(
            container_logs_capture=lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="")
        )
        source = ContainerLogSource(backend, ["c1"])
        assert source.fetch("s", "e").status is CollectorStatus.SOURCE_UNAVAILABLE

    def test_empty_output_is_empty_ok(self):
        backend = types.SimpleNamespace(
            container_logs_capture=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="  ")
        )
        source = ContainerLogSource(backend, ["c1"])
        assert source.fetch("s", "e").status is CollectorStatus.EMPTY_OK

    def test_output_becomes_records(self):
        backend = types.SimpleNamespace(
            container_logs_capture=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="line1\nline2")
        )
        source = ContainerLogSource(backend, ["c1"])
        result = source.fetch("s", "e")
        assert result.status is CollectorStatus.OK
        assert result.records[0]["container"] == "c1"


class TestSocWindowedSource:
    def test_none_is_source_unavailable(self):
        source = soc_windowed_source(lambda s, e: None)
        assert source.fetch("s", "e").status is CollectorStatus.SOURCE_UNAVAILABLE

    def test_empty_list_is_empty_ok(self):
        source = soc_windowed_source(lambda s, e: [])
        assert source.fetch("s", "e").status is CollectorStatus.EMPTY_OK

    def test_events_are_ok(self):
        source = soc_windowed_source(lambda s, e: [{"alert": 1}])
        result = source.fetch("s", "e")
        assert result.status is CollectorStatus.OK
        assert result.records == [{"alert": 1}]


class TestWiring:
    def test_builds_collectors_for_known_ids(self):
        source = _FakeSource(SourceResult(status=CollectorStatus.EMPTY_OK))
        collectors = build_collectors({"aptl.collector.mcp-red": source})
        assert collectors["aptl.collector.mcp-red"].registration_id == "aptl.collector.mcp-red"

    def test_unknown_registration_id_is_rejected(self):
        source = _FakeSource(SourceResult(status=CollectorStatus.EMPTY_OK))
        with pytest.raises(ValueError, match="unknown collector registration id"):
            build_collectors({"aptl.collector.NOPE": source})

    def test_the_five_builtins_are_registered(self):
        assert BUILTIN_REGISTRATION_IDS == frozenset(
            {
                "aptl.collector.mcp-red",
                "aptl.collector.container-logs",
                "aptl.collector.suricata-eve",
                "aptl.collector.wazuh-alerts",
                "aptl.collector.tempo-traces",
            }
        )
