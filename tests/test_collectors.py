"""Unit tests for data collectors."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from aptl.core.collectors import (
    collect_container_logs,
    collect_suricata_eve,
    collect_thehive_cases,
    collect_misp_events,
    collect_shuffle_executions,
    collect_traces,
    collect_wazuh_alerts,
)


class TestCollectTraces:
    """Tests for Tempo trace collection."""

    @patch("aptl.core.collectors._curl_json")
    def test_returns_spans_from_tempo(self, mock_curl):
        mock_curl.return_value = {
            "resourceSpans": [
                {
                    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "aptl-cli"}}]},
                    "scopeSpans": [
                        {
                            "spans": [
                                {"name": "aptl.scenario.run", "traceId": "abc123"},
                                {"name": "execute_tool", "traceId": "abc123"},
                            ]
                        }
                    ],
                }
            ]
        }

        spans = collect_traces("abc123def456" * 2 + "0" * 8)
        assert len(spans) == 2
        assert spans[0]["name"] == "aptl.scenario.run"
        assert spans[1]["name"] == "execute_tool"
        # Resource should be attached to each span
        assert "resource" in spans[0]

    @patch("aptl.core.collectors._curl_json")
    def test_returns_empty_on_failure(self, mock_curl):
        mock_curl.return_value = None
        spans = collect_traces("abc123")
        assert spans == []

    def test_returns_empty_without_trace_id(self):
        spans = collect_traces("")
        assert spans == []

    @patch("aptl.core.collectors._curl_json")
    def test_handles_empty_response(self, mock_curl):
        mock_curl.return_value = {}
        spans = collect_traces("abc123")
        assert spans == []

    @patch("aptl.core.collectors._curl_json")
    def test_handles_batches_format(self, mock_curl):
        """Tempo v2 uses 'batches' key."""
        mock_curl.return_value = {
            "batches": [
                {
                    "resource": {},
                    "scopeSpans": [
                        {"spans": [{"name": "test-span"}]}
                    ],
                }
            ]
        }
        spans = collect_traces("abc123")
        assert len(spans) == 1
        assert spans[0]["name"] == "test-span"

    @patch("aptl.core.collectors._curl_json")
    def test_uses_tempo_url_env(self, mock_curl, monkeypatch):
        mock_curl.return_value = {"resourceSpans": []}
        monkeypatch.setenv("TEMPO_URL", "http://custom:9999")

        collect_traces("abc123")

        called_url = mock_curl.call_args[0][0]
        assert called_url.startswith("http://custom:9999/api/traces/")

    @patch("aptl.core.collectors._curl_json")
    def test_uses_explicit_tempo_url(self, mock_curl):
        mock_curl.return_value = {"resourceSpans": []}

        collect_traces("abc123", tempo_url="http://explicit:7777")

        called_url = mock_curl.call_args[0][0]
        assert called_url == "http://explicit:7777/api/traces/abc123"

    @patch("aptl.core.collectors._curl_json")
    def test_does_not_mutate_input_spans(self, mock_curl):
        """collect_traces should not mutate the parsed Tempo response."""
        original_span = {"name": "test", "traceId": "abc"}
        mock_curl.return_value = {
            "resourceSpans": [
                {
                    "resource": {"attrs": "val"},
                    "scopeSpans": [{"spans": [original_span]}],
                }
            ]
        }
        spans = collect_traces("abc123")
        assert len(spans) == 1
        assert "resource" in spans[0]
        # Original span dict should not have been mutated
        assert "resource" not in original_span


class TestCollectContainerLogs:
    """Tests for container log collection."""

    def test_collects_logs(self):
        backend = MagicMock()
        backend.container_logs_capture.return_value = MagicMock(
            returncode=0,
            stdout="log line 1\nlog line 2\n",
            stderr="",
        )

        logs = collect_container_logs(
            ["aptl-victim"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            backend,
        )
        assert "aptl-victim" in logs
        assert "log line 1" in logs["aptl-victim"]
        backend.container_logs_capture.assert_called_once_with(
            "aptl-victim",
            since="2025-01-01T00:00:00+00:00",
            until="2025-01-01T23:59:59+00:00",
            timeout=30,
        )

    def test_skips_failed_container(self):
        backend = MagicMock()
        backend.container_logs_capture.return_value = MagicMock(
            returncode=1, stdout="", stderr="error"
        )

        logs = collect_container_logs(
            ["aptl-missing"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            backend,
        )
        assert logs == {}

    def test_combines_stdout_stderr(self):
        backend = MagicMock()
        backend.container_logs_capture.return_value = MagicMock(
            returncode=0,
            stdout="stdout line",
            stderr="stderr line",
        )

        logs = collect_container_logs(
            ["aptl-victim"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            backend,
        )
        assert "stdout line" in logs["aptl-victim"]
        assert "stderr line" in logs["aptl-victim"]

    def test_skips_empty_output(self):
        backend = MagicMock()
        backend.container_logs_capture.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )

        logs = collect_container_logs(
            ["aptl-victim"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            backend,
        )
        assert logs == {}


class TestCollectWazuhAlerts:
    """Tests for Wazuh alert collection."""

    @patch("aptl.core.collectors._curl_json")
    def test_returns_empty_on_failure(self, mock_curl):
        mock_curl.return_value = None

        result = collect_wazuh_alerts(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
        )
        assert result == []

    @patch("aptl.core.collectors._curl_json")
    def test_collects_alerts(self, mock_curl):
        mock_curl.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"rule": {"id": "1"}, "@timestamp": "2025-01-01T12:00:00"}},
                    {"_source": {"rule": {"id": "2"}, "@timestamp": "2025-01-01T12:01:00"}},
                ]
            },
            "_scroll_id": None,
        }

        result = collect_wazuh_alerts(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
        )
        assert len(result) == 2
        assert result[0]["rule"]["id"] == "1"


class TestCollectSuricataEve:
    """Tests for Suricata EVE collection."""

    def test_returns_empty_when_container_missing(self):
        backend = MagicMock()
        backend.container_exec.return_value = MagicMock(
            returncode=1, stdout="", stderr="No such container"
        )

        result = collect_suricata_eve(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            backend,
        )
        assert result == []

    def test_filters_by_time(self):
        entries = [
            json.dumps({"timestamp": "2025-01-01T10:00:00+00:00", "event_type": "dns"}),
            json.dumps({"timestamp": "2025-01-01T12:00:00+00:00", "event_type": "alert"}),
            json.dumps({"timestamp": "2025-01-01T14:00:00+00:00", "event_type": "flow"}),
        ]
        backend = MagicMock()
        backend.container_exec.return_value = MagicMock(
            returncode=0, stdout="\n".join(entries), stderr=""
        )

        result = collect_suricata_eve(
            "2025-01-01T11:00:00+00:00",
            "2025-01-01T13:00:00+00:00",
            backend,
        )
        assert len(result) == 1
        assert result[0]["event_type"] == "alert"


class TestCollectTheHiveCases:
    """Tests for TheHive case collection."""

    def test_returns_empty_without_api_key(self):
        result = collect_thehive_cases(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="",
        )
        assert result == []

    @patch("aptl.core.collectors._curl_json")
    def test_returns_cases(self, mock_curl):
        mock_curl.return_value = [{"_id": "case1"}, {"_id": "case2"}]

        result = collect_thehive_cases(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="test-key",
        )
        assert len(result) == 2

    @patch("aptl.core.collectors._curl_json")
    def test_query_includes_end_iso_upper_bound(self, mock_curl):
        mock_curl.return_value = []
        end = "2025-01-01T23:59:59+00:00"

        collect_thehive_cases(
            "2025-01-01T00:00:00+00:00",
            end,
            api_key="test-key",
        )

        body = mock_curl.call_args[1]["body"]
        filter_clause = body["query"][1]
        assert "_and" in filter_clause
        lte_found = any(
            "_lte" in clause and clause["_lte"]["_value"] == end
            for clause in filter_clause["_and"]
        )
        assert lte_found, "Query must include _lte filter with end_iso"

    @patch("aptl.core.collectors._curl_json")
    def test_query_bounds_both_start_and_end(self, mock_curl):
        mock_curl.return_value = [
            {"_id": "in-window", "_createdAt": "2025-01-01T12:00:00+00:00"},
        ]
        start = "2025-01-01T00:00:00+00:00"
        end = "2025-01-01T23:59:59+00:00"

        collect_thehive_cases(start, end, api_key="test-key")

        body = mock_curl.call_args[1]["body"]
        filter_clause = body["query"][1]
        and_clauses = filter_clause["_and"]
        gte_found = any(
            "_gte" in c and c["_gte"]["_value"] == start for c in and_clauses
        )
        lte_found = any(
            "_lte" in c and c["_lte"]["_value"] == end for c in and_clauses
        )
        assert gte_found and lte_found


class TestCollectMISPEvents:
    """Tests for MISP event collection."""

    def test_returns_empty_without_api_key(self):
        result = collect_misp_events(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="",
        )
        assert result == []

    @patch("aptl.core.collectors._curl_json")
    def test_returns_events(self, mock_curl):
        mock_curl.return_value = {"response": [{"Event": {"id": "1", "timestamp": "1735689600"}}]}

        result = collect_misp_events(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="test-key",
        )
        assert len(result) == 1

    @patch("aptl.core.collectors._curl_json")
    def test_filters_events_after_end_time(self, mock_curl):
        # 1735689600 = 2025-01-01T00:00:00 UTC (in window)
        # 1735776000 = 2025-01-02T00:00:00 UTC (after window)
        mock_curl.return_value = {
            "response": [
                {"Event": {"id": "1", "timestamp": "1735689600"}},
                {"Event": {"id": "2", "timestamp": "1735776000"}},
            ]
        }

        result = collect_misp_events(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="test-key",
        )
        assert len(result) == 1
        assert result[0]["Event"]["id"] == "1"

    @patch("aptl.core.collectors._curl_json")
    def test_keeps_events_without_timestamp(self, mock_curl):
        mock_curl.return_value = {
            "response": [
                {"Event": {"id": "1"}},
                {"Event": {"id": "2", "timestamp": ""}},
            ]
        }

        result = collect_misp_events(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="test-key",
        )
        assert len(result) == 2


class TestCollectShuffleExecutions:
    """Tests for Shuffle execution collection."""

    def test_returns_empty_without_api_key(self):
        result = collect_shuffle_executions(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="",
        )
        assert result == []

    @patch("aptl.core.collectors._curl_json")
    def test_returns_empty_on_failure(self, mock_curl):
        mock_curl.return_value = None

        result = collect_shuffle_executions(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="test-key",
        )
        assert result == []
