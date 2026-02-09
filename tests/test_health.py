"""Tests for container health checking logic.

Tests exercise retry logic, timeout handling, and health status aggregation.
All Docker API calls are mocked.
"""

from unittest.mock import MagicMock, patch

import pytest


class TestContainerHealthCheck:
    """Tests for individual container health checks."""

    def test_healthy_container_returns_healthy(self):
        """A running container with healthy status should return healthy."""
        from aptl.core.health import check_container_health

        mock_client = MagicMock()
        container = MagicMock()
        container.status = "running"
        container.attrs = {"State": {"Health": {"Status": "healthy"}}}
        mock_client.containers.get.return_value = container

        result = check_container_health("aptl-victim", client=mock_client)

        assert result.healthy is True
        assert result.container_name == "aptl-victim"
        assert result.status == "healthy"

    def test_unhealthy_container_returns_unhealthy(self):
        """A container with unhealthy status should return unhealthy."""
        from aptl.core.health import check_container_health

        mock_client = MagicMock()
        container = MagicMock()
        container.status = "running"
        container.attrs = {"State": {"Health": {"Status": "unhealthy"}}}
        mock_client.containers.get.return_value = container

        result = check_container_health("aptl-victim", client=mock_client)

        assert result.healthy is False
        assert result.status == "unhealthy"

    def test_missing_container_returns_not_found(self):
        """If container doesn't exist, should return error result."""
        from aptl.core.health import check_container_health, ContainerNotFoundError

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = ContainerNotFoundError("aptl-victim")

        result = check_container_health("aptl-victim", client=mock_client)

        assert result.healthy is False
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_container_without_healthcheck_uses_running_status(self):
        """Containers without a healthcheck should use running status as proxy."""
        from aptl.core.health import check_container_health

        mock_client = MagicMock()
        container = MagicMock()
        container.status = "running"
        container.attrs = {"State": {}}  # No Health key
        mock_client.containers.get.return_value = container

        result = check_container_health("aptl-kali", client=mock_client)

        assert result.healthy is True
        assert result.status == "running"

    def test_stopped_container_is_unhealthy(self):
        """A stopped container should be reported as unhealthy."""
        from aptl.core.health import check_container_health

        mock_client = MagicMock()
        container = MagicMock()
        container.status = "exited"
        container.attrs = {"State": {}}
        mock_client.containers.get.return_value = container

        result = check_container_health("aptl-victim", client=mock_client)

        assert result.healthy is False
        assert result.status == "exited"


class TestHealthCheckRetry:
    """Tests for retry logic in health checking."""

    def test_retries_on_transient_failure(self):
        """Should retry when container is temporarily unavailable."""
        from aptl.core.health import check_container_health, ContainerNotFoundError

        mock_client = MagicMock()
        healthy_container = MagicMock()
        healthy_container.status = "running"
        healthy_container.attrs = {"State": {"Health": {"Status": "healthy"}}}

        # First call fails, second succeeds
        mock_client.containers.get.side_effect = [
            ContainerNotFoundError("aptl-victim"),
            healthy_container,
        ]

        result = check_container_health(
            "aptl-victim", client=mock_client, retries=2, retry_delay=0
        )

        assert result.healthy is True
        assert mock_client.containers.get.call_count == 2

    def test_exhausts_retries_then_fails(self):
        """After all retries exhausted, should return failure."""
        from aptl.core.health import check_container_health, ContainerNotFoundError

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = ContainerNotFoundError("x")

        result = check_container_health(
            "x", client=mock_client, retries=3, retry_delay=0
        )

        assert result.healthy is False
        assert mock_client.containers.get.call_count == 3

    def test_zero_retries_means_single_attempt(self):
        """retries=1 should mean exactly one attempt."""
        from aptl.core.health import check_container_health, ContainerNotFoundError

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = ContainerNotFoundError("x")

        result = check_container_health(
            "x", client=mock_client, retries=1, retry_delay=0
        )

        assert mock_client.containers.get.call_count == 1


class TestLabHealthSummary:
    """Tests for aggregated lab health checking."""

    def test_all_healthy_returns_healthy(self):
        """If all checked containers are healthy, overall is healthy."""
        from aptl.core.health import HealthResult, aggregate_health

        results = [
            HealthResult(container_name="a", healthy=True, status="healthy"),
            HealthResult(container_name="b", healthy=True, status="healthy"),
        ]

        summary = aggregate_health(results)

        assert summary.all_healthy is True
        assert summary.healthy_count == 2
        assert summary.unhealthy_count == 0

    def test_any_unhealthy_returns_unhealthy(self):
        """If any container is unhealthy, overall is unhealthy."""
        from aptl.core.health import HealthResult, aggregate_health

        results = [
            HealthResult(container_name="a", healthy=True, status="healthy"),
            HealthResult(container_name="b", healthy=False, status="exited"),
        ]

        summary = aggregate_health(results)

        assert summary.all_healthy is False
        assert summary.healthy_count == 1
        assert summary.unhealthy_count == 1

    def test_empty_results_returns_unhealthy(self):
        """No containers means the lab isn't running (unhealthy)."""
        from aptl.core.health import aggregate_health

        summary = aggregate_health([])

        assert summary.all_healthy is False
        assert summary.healthy_count == 0
