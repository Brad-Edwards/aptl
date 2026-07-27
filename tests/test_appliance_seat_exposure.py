"""Host exposure inventory tests for the appliance seat launcher."""

from __future__ import annotations

from unittest.mock import patch

from aptl.appliance.seat.exposure import audit_host_process_inventory


def test_audit_host_process_inventory_probes_docker_by_default() -> None:
    with patch(
        "aptl.appliance.seat.exposure._docker_daemon_running",
        return_value=True,
    ) as probe:
        report = audit_host_process_inventory()

    probe.assert_called_once()
    assert report.passed is False
    assert "host.exposure.docker-daemon-present" in report.findings
