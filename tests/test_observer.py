"""Tests for the Wazuh Alert Observer module.

Tests cover connection setup, SSL context building, auth header generation,
query_wazuh_alerts with mocked urllib, and check_alert_objective logic.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from aptl.core.objectives import ObjectiveResult, ObjectiveStatus
from aptl.core.observer import (
    WazuhConnection,
    _build_auth_header,
    _build_ssl_context,
    check_alert_objective,
    query_wazuh_alerts,
)
from aptl.core.scenarios import ObserverError, WazuhAlertValidation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _conn(
    url: str = "https://localhost:9200",
    username: str = "admin",
    password: str = "secret",
    verify_ssl: bool = False,
) -> WazuhConnection:
    return WazuhConnection(
        url=url,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
    )


def _validation(
    min_matches: int = 1,
    query: dict | None = None,
) -> WazuhAlertValidation:
    return WazuhAlertValidation(
        query=query or {"match": {"rule.id": "1000"}},
        min_matches=min_matches,
    )


def _mock_urlopen_response(data: dict):
    """Create a mock context manager for urllib.request.urlopen."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(data).encode("utf-8")
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)
    return mock_response


# ---------------------------------------------------------------------------
# WazuhConnection
# ---------------------------------------------------------------------------


class TestWazuhConnection:
    """Tests for the WazuhConnection dataclass."""

    def test_defaults(self):
        conn = WazuhConnection(url="https://localhost:9200", username="u", password="p")
        assert conn.verify_ssl is False

    def test_all_fields(self):
        conn = _conn(verify_ssl=True)
        assert conn.url == "https://localhost:9200"
        assert conn.username == "admin"
        assert conn.password == "secret"
        assert conn.verify_ssl is True


# ---------------------------------------------------------------------------
# _build_ssl_context
# ---------------------------------------------------------------------------


class TestBuildSslContext:
    """Tests for SSL context creation."""

    def test_verify_false_disables_checks(self):
        ctx = _build_ssl_context(False)
        assert ctx.check_hostname is False

    def test_verify_true_keeps_defaults(self):
        ctx = _build_ssl_context(True)
        assert ctx.check_hostname is True


# ---------------------------------------------------------------------------
# _build_auth_header
# ---------------------------------------------------------------------------


class TestBuildAuthHeader:
    """Tests for Basic auth header generation."""

    def test_basic_auth_format(self):
        header = _build_auth_header("admin", "secret")
        assert header.startswith("Basic ")

    def test_encodes_correctly(self):
        import base64

        header = _build_auth_header("user", "pass")
        encoded = header.split(" ", 1)[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert decoded == "user:pass"

    def test_handles_special_chars(self):
        import base64

        header = _build_auth_header("admin", "p@ss:w0rd!")
        encoded = header.split(" ", 1)[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert decoded == "admin:p@ss:w0rd!"


# ---------------------------------------------------------------------------
# query_wazuh_alerts
# ---------------------------------------------------------------------------


class TestQueryWazuhAlerts:
    """Tests for executing Elasticsearch queries."""

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_returns_sources(self, mock_urlopen):
        """Should extract _source from each hit."""
        response_data = {
            "hits": {
                "hits": [
                    {"_source": {"rule.id": "1000", "agent.name": "victim"}},
                    {"_source": {"rule.id": "1000", "agent.name": "kali"}},
                ]
            }
        }
        mock_urlopen.return_value = _mock_urlopen_response(response_data)

        results = query_wazuh_alerts(_conn(), {"match_all": {}})

        assert len(results) == 2
        assert results[0]["rule.id"] == "1000"

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_empty_results(self, mock_urlopen):
        """Should return empty list when no hits."""
        mock_urlopen.return_value = _mock_urlopen_response(
            {"hits": {"hits": []}}
        )

        results = query_wazuh_alerts(_conn(), {"match_all": {}})
        assert results == []

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_custom_index_pattern(self, mock_urlopen):
        """Should use the specified index pattern in the URL."""
        mock_urlopen.return_value = _mock_urlopen_response(
            {"hits": {"hits": []}}
        )

        query_wazuh_alerts(_conn(), {"match_all": {}}, index_pattern="custom-*")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert "custom-*" in request.full_url

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_sends_correct_body(self, mock_urlopen):
        """Should send query and size in the request body."""
        mock_urlopen.return_value = _mock_urlopen_response(
            {"hits": {"hits": []}}
        )

        query = {"match": {"rule.id": "1000"}}
        query_wazuh_alerts(_conn(), query, size=50)

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data)
        assert body["query"] == query
        assert body["size"] == 50

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_sends_auth_header(self, mock_urlopen):
        """Should include Basic auth header."""
        mock_urlopen.return_value = _mock_urlopen_response(
            {"hits": {"hits": []}}
        )

        query_wazuh_alerts(_conn(username="admin", password="secret"), {"match_all": {}})

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert "Authorization" in request.headers
        assert request.headers["Authorization"].startswith("Basic ")

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_http_error_raises_observer_error(self, mock_urlopen):
        """HTTP errors should be wrapped in ObserverError."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://localhost:9200",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=MagicMock(read=MagicMock(return_value=b"Unauthorized")),
        )

        with pytest.raises(ObserverError, match="HTTP 401"):
            query_wazuh_alerts(_conn(), {"match_all": {}})

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_url_error_raises_observer_error(self, mock_urlopen):
        """URL/network errors should be wrapped in ObserverError."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with pytest.raises(ObserverError, match="query failed"):
            query_wazuh_alerts(_conn(), {"match_all": {}})

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_os_error_raises_observer_error(self, mock_urlopen):
        """OS-level errors should be wrapped in ObserverError."""
        mock_urlopen.side_effect = OSError("Network unreachable")

        with pytest.raises(ObserverError, match="query failed"):
            query_wazuh_alerts(_conn(), {"match_all": {}})

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_invalid_json_response_raises_observer_error(self, mock_urlopen):
        """Invalid JSON responses should be wrapped in ObserverError."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"not json"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        with pytest.raises(ObserverError, match="Invalid JSON"):
            query_wazuh_alerts(_conn(), {"match_all": {}})

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_missing_hits_key(self, mock_urlopen):
        """Response without 'hits' key should return empty list."""
        mock_urlopen.return_value = _mock_urlopen_response({"took": 1})

        results = query_wazuh_alerts(_conn(), {"match_all": {}})
        assert results == []

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_hits_without_source(self, mock_urlopen):
        """Hits missing _source should be skipped."""
        response_data = {
            "hits": {
                "hits": [
                    {"_id": "1"},  # no _source
                    {"_source": {"rule.id": "1000"}},
                ]
            }
        }
        mock_urlopen.return_value = _mock_urlopen_response(response_data)

        results = query_wazuh_alerts(_conn(), {"match_all": {}})
        assert len(results) == 1

    @patch("aptl.core.observer.urllib.request.urlopen")
    def test_url_trailing_slash_handled(self, mock_urlopen):
        """Trailing slashes on the base URL should not cause double slashes."""
        mock_urlopen.return_value = _mock_urlopen_response(
            {"hits": {"hits": []}}
        )

        query_wazuh_alerts(
            _conn(url="https://localhost:9200/"),
            {"match_all": {}},
        )

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert "//" not in request.full_url.replace("https://", "")


# ---------------------------------------------------------------------------
# check_alert_objective
# ---------------------------------------------------------------------------


class TestCheckAlertObjective:
    """Tests for checking wazuh_alert objectives."""

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_completed_when_enough_matches(self, mock_query):
        """Should return COMPLETED when min_matches is met."""
        mock_query.return_value = [{"rule.id": "1000"}]

        result = check_alert_objective(
            _conn(),
            _validation(min_matches=1),
            "2026-02-16T14:30:00+00:00",
        )

        assert result.status == ObjectiveStatus.COMPLETED

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_pending_when_not_enough_matches(self, mock_query):
        """Should return PENDING when min_matches is not met."""
        mock_query.return_value = []

        result = check_alert_objective(
            _conn(),
            _validation(min_matches=3),
            "2026-02-16T14:30:00+00:00",
        )

        assert result.status == ObjectiveStatus.PENDING

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_includes_match_count_in_details(self, mock_query):
        """Details should describe how many matches were found."""
        mock_query.return_value = [{"rule.id": "1000"}, {"rule.id": "1000"}]

        result = check_alert_objective(
            _conn(),
            _validation(min_matches=2),
            "2026-02-16T14:30:00+00:00",
        )

        assert "2" in result.details

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_pending_on_query_failure(self, mock_query):
        """Should return PENDING when the query raises ObserverError."""
        mock_query.side_effect = ObserverError("Connection refused")

        result = check_alert_objective(
            _conn(),
            _validation(),
            "2026-02-16T14:30:00+00:00",
        )

        assert result.status == ObjectiveStatus.PENDING
        assert "failed" in result.details.lower()

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_builds_time_bounded_query(self, mock_query):
        """Should combine user query with a time range filter."""
        mock_query.return_value = []

        user_query = {"match": {"rule.id": "1000"}}
        check_alert_objective(
            _conn(),
            _validation(query=user_query),
            "2026-02-16T14:30:00+00:00",
        )

        call_args = mock_query.call_args
        # Positional args: (conn, combined_query), keyword: size=...
        query = call_args[0][1]

        assert "bool" in query
        must_clauses = query["bool"]["must"]
        assert len(must_clauses) == 2
        # First clause is user query
        assert must_clauses[0] == user_query
        # Second clause is time range
        assert "range" in must_clauses[1]

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_completed_has_timestamp(self, mock_query):
        """Completed results should have a completed_at timestamp."""
        mock_query.return_value = [{"rule.id": "1000"}]

        result = check_alert_objective(
            _conn(),
            _validation(),
            "2026-02-16T14:30:00+00:00",
        )

        assert result.completed_at is not None

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_objective_id_set_on_completed(self, mock_query):
        """objective_id should be set on the returned result."""
        mock_query.return_value = [{"rule.id": "1000"}]

        result = check_alert_objective(
            _conn(),
            _validation(),
            "2026-02-16T14:30:00+00:00",
            objective_id="wazuh-obj-1",
        )

        assert result.objective_id == "wazuh-obj-1"

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_objective_id_set_on_pending(self, mock_query):
        """objective_id should be set even when result is PENDING."""
        mock_query.return_value = []

        result = check_alert_objective(
            _conn(),
            _validation(min_matches=5),
            "2026-02-16T14:30:00+00:00",
            objective_id="wazuh-obj-2",
        )

        assert result.objective_id == "wazuh-obj-2"
        assert result.status == ObjectiveStatus.PENDING

    @patch("aptl.core.observer.query_wazuh_alerts")
    def test_objective_id_set_on_failure(self, mock_query):
        """objective_id should be set even when the query fails."""
        mock_query.side_effect = ObserverError("Connection refused")

        result = check_alert_objective(
            _conn(),
            _validation(),
            "2026-02-16T14:30:00+00:00",
            objective_id="wazuh-obj-3",
        )

        assert result.objective_id == "wazuh-obj-3"
        assert result.status == ObjectiveStatus.PENDING
