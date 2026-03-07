"""Unit tests for data collectors."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from aptl.core.collectors import (
    collect_container_logs,
    collect_mcp_traces,
    collect_suricata_eve,
    collect_thehive_cases,
    collect_misp_events,
    collect_shuffle_executions,
    collect_wazuh_alerts,
)


class TestCollectMCPTraces:
    """Tests for MCP trace collection."""

    def test_collect_from_empty_dir(self, tmp_path):
        traces = collect_mcp_traces(
            tmp_path, "2020-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00"
        )
        assert traces == []

    def test_collect_nonexistent_dir(self, tmp_path):
        traces = collect_mcp_traces(
            tmp_path / "nope", "2020-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00"
        )
        assert traces == []

    def test_collect_filters_by_time(self, tmp_path):
        traces = [
            {"timestamp": "2025-01-01T10:00:00+00:00", "tool_name": "early"},
            {"timestamp": "2025-01-01T12:00:00+00:00", "tool_name": "in_window"},
            {"timestamp": "2025-01-01T14:00:00+00:00", "tool_name": "late"},
        ]
        trace_file = tmp_path / "server.jsonl"
        trace_file.write_text(
            "\n".join(json.dumps(t) for t in traces) + "\n"
        )

        result = collect_mcp_traces(
            tmp_path,
            "2025-01-01T11:00:00+00:00",
            "2025-01-01T13:00:00+00:00",
        )
        assert len(result) == 1
        assert result[0]["tool_name"] == "in_window"

    def test_collect_merges_multiple_files(self, tmp_path):
        (tmp_path / "server-a.jsonl").write_text(
            json.dumps({"timestamp": "2025-01-01T12:00:00+00:00", "server": "a"}) + "\n"
        )
        (tmp_path / "server-b.jsonl").write_text(
            json.dumps({"timestamp": "2025-01-01T11:00:00+00:00", "server": "b"}) + "\n"
        )

        result = collect_mcp_traces(
            tmp_path,
            "2025-01-01T10:00:00+00:00",
            "2025-01-01T13:00:00+00:00",
        )
        assert len(result) == 2
        # Should be sorted chronologically
        assert result[0]["server"] == "b"
        assert result[1]["server"] == "a"

    def test_collect_skips_invalid_json(self, tmp_path):
        (tmp_path / "bad.jsonl").write_text(
            "not json\n"
            + json.dumps({"timestamp": "2025-01-01T12:00:00+00:00", "ok": True})
            + "\n"
        )

        result = collect_mcp_traces(
            tmp_path,
            "2025-01-01T10:00:00+00:00",
            "2025-01-01T13:00:00+00:00",
        )
        assert len(result) == 1
        assert result[0]["ok"] is True


class TestCollectContainerLogs:
    """Tests for container log collection."""

    @patch("aptl.core.collectors._run_cmd")
    def test_collects_logs(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="log line 1\nlog line 2\n",
            stderr="",
        )

        logs = collect_container_logs(
            ["aptl-victim"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
        )
        assert "aptl-victim" in logs
        assert "log line 1" in logs["aptl-victim"]

    @patch("aptl.core.collectors._run_cmd")
    def test_skips_failed_container(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")

        logs = collect_container_logs(
            ["aptl-missing"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
        )
        assert logs == {}

    @patch("aptl.core.collectors._run_cmd")
    def test_combines_stdout_stderr(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="stdout line",
            stderr="stderr line",
        )

        logs = collect_container_logs(
            ["aptl-victim"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
        )
        assert "stdout line" in logs["aptl-victim"]
        assert "stderr line" in logs["aptl-victim"]

    @patch("aptl.core.collectors._run_cmd")
    def test_skips_empty_output(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        logs = collect_container_logs(
            ["aptl-victim"],
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
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

    @patch("aptl.core.collectors._run_cmd")
    def test_returns_empty_when_container_missing(self, mock_run):
        mock_run.return_value = None

        result = collect_suricata_eve(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
        )
        assert result == []

    @patch("aptl.core.collectors._run_cmd")
    def test_filters_by_time(self, mock_run):
        entries = [
            json.dumps({"timestamp": "2025-01-01T10:00:00+00:00", "event_type": "dns"}),
            json.dumps({"timestamp": "2025-01-01T12:00:00+00:00", "event_type": "alert"}),
            json.dumps({"timestamp": "2025-01-01T14:00:00+00:00", "event_type": "flow"}),
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout="\n".join(entries)
        )

        result = collect_suricata_eve(
            "2025-01-01T11:00:00+00:00",
            "2025-01-01T13:00:00+00:00",
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
        mock_curl.return_value = {"response": [{"Event": {"id": "1"}}]}

        result = collect_misp_events(
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T23:59:59+00:00",
            api_key="test-key",
        )
        assert len(result) == 1


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
