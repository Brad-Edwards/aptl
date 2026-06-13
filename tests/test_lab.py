"""Tests for lab lifecycle management.

Tests exercise our logic for starting/stopping the lab, profile selection,
compose command construction, and full orchestration. All subprocess/docker
calls are mocked.
"""

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


class TestComposeCommandBuilder:
    """Tests for building docker compose commands."""

    def test_build_up_command_with_profiles(self):
        """Should construct 'docker compose --profile X up -d' with correct profiles."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("up", profiles=["wazuh", "victim", "kali"])
        assert cmd[0] == "docker"
        assert cmd[1] == "compose"
        assert "--profile" in cmd
        assert "wazuh" in cmd
        assert "victim" in cmd
        assert "kali" in cmd
        assert "up" in cmd
        assert "-d" in cmd

    def test_build_down_command(self):
        """Should construct 'docker compose down'."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("down", profiles=[])
        assert "down" in cmd
        assert "-d" not in cmd

    def test_build_command_with_no_profiles(self):
        """An empty profile list should not add --profile flags."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("up", profiles=[])
        assert "--profile" not in cmd

    def test_build_ps_command(self):
        """Should construct 'docker compose ps' for status."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("ps", profiles=["wazuh"])
        assert "ps" in cmd

    def test_build_up_command_includes_build_flag(self):
        """Should include --build before -d for up action (C2)."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("up", profiles=["wazuh"])
        assert "--build" in cmd
        assert "-d" in cmd
        # --build should come before -d
        build_idx = cmd.index("--build")
        d_idx = cmd.index("-d")
        assert build_idx < d_idx

    def test_build_down_command_has_no_build_flag(self):
        """Should not include --build for down action."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("down", profiles=[])
        assert "--build" not in cmd


class TestLabStart:
    """Tests for lab start logic."""

    def test_start_calls_compose_up(self, mock_subprocess):
        """start_lab should invoke docker compose up with correct profiles."""
        from aptl.core.config import AptlConfig
        from aptl.core.lab import start_lab

        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "victim": True, "kali": False, "reverse": False},
        )
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = start_lab(config)

        assert result.success is True
        mock_subprocess.assert_called_once()
        cmd_args = mock_subprocess.call_args[0][0]
        assert "up" in cmd_args
        assert "wazuh" in cmd_args
        assert "victim" in cmd_args
        assert "kali" not in cmd_args

    def test_start_returns_failure_on_nonzero_exit(self, mock_subprocess):
        """If docker compose fails, start_lab should return failure result."""
        from aptl.core.config import AptlConfig
        from aptl.core.lab import start_lab

        config = AptlConfig(lab={"name": "test"})
        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr="Error: something went wrong"
        )

        result = start_lab(config)

        assert result.success is False
        assert "something went wrong" in result.error

    def test_start_uses_project_dir(self, mock_subprocess):
        """start_lab should pass cwd to subprocess when project_dir is given."""
        from aptl.core.config import AptlConfig
        from aptl.core.lab import start_lab
        from pathlib import Path

        config = AptlConfig(lab={"name": "test"})
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        start_lab(config, project_dir=Path("/opt/aptl"))

        kwargs = mock_subprocess.call_args[1]
        assert kwargs["cwd"] == Path("/opt/aptl")


class TestLabStop:
    """Tests for lab stop logic."""

    def test_stop_calls_compose_down(self, mock_subprocess):
        """stop_lab should invoke docker compose down."""
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = stop_lab()

        assert result.success is True
        cmd_args = mock_subprocess.call_args[0][0]
        assert "down" in cmd_args

    def test_stop_with_volumes_flag(self, mock_subprocess):
        """stop_lab with remove_volumes=True should pass -v flag."""
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        stop_lab(remove_volumes=True)

        cmd_args = mock_subprocess.call_args[0][0]
        assert "-v" in cmd_args

    def test_stop_returns_failure_on_error(self, mock_subprocess):
        """If docker compose down fails, stop_lab returns failure."""
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr="Cannot stop"
        )

        result = stop_lab()

        assert result.success is False

    def test_stop_uses_all_profiles_when_no_config(self, mock_subprocess, tmp_path):
        """stop_lab should fall back to all profiles when no aptl.json exists."""
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = stop_lab(project_dir=tmp_path)

        assert result.success is True
        cmd_args = mock_subprocess.call_args[0][0]
        # Should include all fallback profiles
        assert "wazuh" in cmd_args
        assert "victim" in cmd_args
        assert "kali" in cmd_args
        assert "soc" in cmd_args

    def test_stop_uses_config_profiles_when_available(self, mock_subprocess, tmp_path):
        """stop_lab should load profiles from aptl.json when present."""
        import json
        from aptl.core.lab import stop_lab

        (tmp_path / "aptl.json").write_text(json.dumps({
            "lab": {"name": "test"},
            "containers": {"victim": True, "kali": False, "wazuh": True},
        }))
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = stop_lab(project_dir=tmp_path)

        assert result.success is True
        cmd_args = mock_subprocess.call_args[0][0]
        assert "victim" in cmd_args
        assert "wazuh" in cmd_args


class TestLabStatus:
    """Tests for lab status checking."""

    def test_status_parses_compose_ps_output(self, mock_subprocess):
        """lab_status should parse docker compose ps output."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout='[{"Name":"aptl-victim","State":"running","Health":"healthy"}]',
            stderr="",
        )

        status = lab_status()

        assert status.running is True
        assert len(status.containers) == 1
        assert status.containers[0]["Name"] == "aptl-victim"

    def test_status_returns_not_running_when_no_containers(self, mock_subprocess):
        """If no containers are returned, status should indicate not running."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout="[]", stderr=""
        )

        status = lab_status()

        assert status.running is False
        assert len(status.containers) == 0

    def test_status_parses_ndjson_output(self, mock_subprocess):
        """lab_status should handle NDJSON (one JSON object per line)."""
        from aptl.core.lab import lab_status

        ndjson = (
            '{"Name":"aptl-victim","State":"running","Health":"healthy"}\n'
            '{"Name":"aptl-kali","State":"running","Health":"healthy"}'
        )
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=ndjson, stderr=""
        )

        status = lab_status()

        assert status.running is True
        assert len(status.containers) == 2

    def test_status_handles_empty_stdout(self, mock_subprocess):
        """lab_status should handle empty output."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )

        status = lab_status()

        assert status.running is False
        assert len(status.containers) == 0

    def test_status_handles_invalid_json(self, mock_subprocess):
        """lab_status should handle malformed JSON output."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout="not json at all", stderr=""
        )

        status = lab_status()

        assert status.running is False
        assert "parse" in status.error.lower()

    def test_status_handles_compose_failure(self, mock_subprocess):
        """If docker compose ps fails, status should handle gracefully."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr="docker not found"
        )

        status = lab_status()

        assert status.running is False
        assert "docker not found" in status.error


class TestCheckBindMounts:
    """Tests for _check_bind_mounts."""

    def test_returns_empty_when_no_compose_file(self, tmp_path):
        from aptl.core.lab import _check_bind_mounts

        assert _check_bind_mounts(tmp_path) == []

    def test_returns_empty_when_all_sources_exist(self, tmp_path):
        from aptl.core.lab import _check_bind_mounts

        (tmp_path / "docker-compose.yml").write_text(
            "services:\n"
            "  web:\n"
            "    volumes:\n"
            "      - ./config:/etc/config\n"
        )
        (tmp_path / "config").mkdir()

        assert _check_bind_mounts(tmp_path) == []

    def test_reports_missing_bind_mount_source(self, tmp_path):
        from aptl.core.lab import _check_bind_mounts

        (tmp_path / "docker-compose.yml").write_text(
            "services:\n"
            "  web:\n"
            "    volumes:\n"
            "      - ./missing_dir:/etc/config\n"
        )

        errors = _check_bind_mounts(tmp_path)
        assert len(errors) == 1
        assert "missing_dir" in errors[0]
        assert "web" in errors[0]

    def test_ignores_non_relative_volumes(self, tmp_path):
        from aptl.core.lab import _check_bind_mounts

        (tmp_path / "docker-compose.yml").write_text(
            "services:\n"
            "  web:\n"
            "    volumes:\n"
            "      - named_volume:/data\n"
        )

        assert _check_bind_mounts(tmp_path) == []

    def test_handles_invalid_yaml(self, tmp_path):
        from aptl.core.lab import _check_bind_mounts

        (tmp_path / "docker-compose.yml").write_text("{{invalid yaml")

        errors = _check_bind_mounts(tmp_path)
        assert len(errors) == 1
        assert "parse" in errors[0].lower() or "Failed" in errors[0]


class TestStartupClassificationTypes:
    """Tests for the StartupOutcome / DiagnosticImpact / StartupDiagnostic types.

    The taxonomy is added in ``aptl.core.lab_types`` per ADR-030. These
    tests pin the enum values and the dataclass shape so other layers
    (CLI, API, web TS mirror) can rely on stable strings.
    """

    def test_startup_outcome_members(self):
        from aptl.core.lab_types import StartupOutcome

        assert StartupOutcome.READY.value == "ready"
        assert StartupOutcome.DEGRADED_USABLE.value == "degraded_usable"
        assert StartupOutcome.DEGRADED_UNUSABLE.value == "degraded_unusable"
        assert StartupOutcome.FAILED.value == "failed"

    def test_diagnostic_impact_members(self):
        from aptl.core.lab_types import DiagnosticImpact

        assert DiagnosticImpact.COSMETIC.value == "cosmetic"
        assert DiagnosticImpact.TELEMETRY.value == "telemetry"
        assert DiagnosticImpact.CAPABILITY.value == "capability"
        assert DiagnosticImpact.READINESS.value == "readiness"

    def test_diagnostic_severity_members(self):
        from aptl.core.lab_types import DiagnosticSeverity

        assert DiagnosticSeverity.INFO.value == "info"
        assert DiagnosticSeverity.WARNING.value == "warning"
        assert DiagnosticSeverity.ERROR.value == "error"

    def test_startup_diagnostic_fields(self):
        from aptl.core.lab_types import (
            DiagnosticImpact,
            DiagnosticSeverity,
            StartupDiagnostic,
        )

        diag = StartupDiagnostic(
            step="wait_for_services",
            component="wazuh_indexer",
            impact=DiagnosticImpact.TELEMETRY,
            severity=DiagnosticSeverity.WARNING,
            message="Indexer did not become ready within 300s",
        )
        assert diag.step == "wait_for_services"
        assert diag.component == "wazuh_indexer"
        assert diag.impact is DiagnosticImpact.TELEMETRY
        assert diag.severity is DiagnosticSeverity.WARNING
        assert diag.message == "Indexer did not become ready within 300s"
        assert diag.operator_action == ""

    def test_startup_diagnostic_component_optional(self):
        from aptl.core.lab_types import (
            DiagnosticImpact,
            DiagnosticSeverity,
            StartupDiagnostic,
        )

        diag = StartupDiagnostic(
            step="pull_images",
            impact=DiagnosticImpact.COSMETIC,
            severity=DiagnosticSeverity.INFO,
            message="Image pre-pull skipped",
        )
        # component defaults to empty string (no special-case in CLI/API)
        assert diag.component == ""

    def test_lab_result_has_outcome_and_diagnostics_with_defaults(self):
        """LabResult must default to READY + empty diagnostics so existing
        callers keep working without touching every constructor."""
        from aptl.core.lab_types import LabResult, StartupOutcome

        r = LabResult(success=True, message="ok")
        assert r.outcome is StartupOutcome.READY
        assert r.diagnostics == []

    def test_lab_result_success_false_without_outcome_normalizes_to_failed(self):
        """A caller constructing LabResult(success=False) without setting
        outcome must not surface as `outcome=ready` — the DTO normalizes
        to FAILED so the wire shape stays consistent across the
        Docker Compose backend, the orchestrator step bodies, and any
        future caller that forgets to set outcome explicitly.

        Codex review (cycle 2) called this the architectural choke point."""
        from aptl.core.lab_types import LabResult, StartupOutcome

        r = LabResult(success=False, error="compose down failed")
        assert r.outcome is StartupOutcome.FAILED
        assert r.success is False

    def test_lab_result_outcome_failed_forces_success_false(self):
        """If the two fields disagree, outcome wins — a FAILED outcome
        is the unambiguous signal, never silently 'successful'."""
        from aptl.core.lab_types import LabResult, StartupOutcome

        r = LabResult(success=True, outcome=StartupOutcome.FAILED, error="x")
        assert r.success is False

    def test_lab_result_degraded_outcomes_keep_success_true(self):
        """A `degraded_*` outcome means the lab is up — back-compat callers
        reading only `success` keep working."""
        from aptl.core.lab_types import LabResult, StartupOutcome

        for outcome in (
            StartupOutcome.DEGRADED_USABLE,
            StartupOutcome.DEGRADED_UNUSABLE,
        ):
            r = LabResult(success=True, outcome=outcome)
            assert r.success is True
            assert r.outcome is outcome

    def test_lab_result_explicit_failed_with_success_false_is_unchanged(self):
        """The orchestrator already wraps short-circuits with both fields
        set consistently; normalization must be a no-op in that case."""
        from aptl.core.lab_types import LabResult, StartupOutcome

        r = LabResult(
            success=False, error="x", outcome=StartupOutcome.FAILED
        )
        assert r.success is False
        assert r.outcome is StartupOutcome.FAILED

    def test_lab_result_success_false_with_degraded_usable_is_corrected(self):
        """Contradictory combination — outcome wins. The lab is up
        (DEGRADED_USABLE), so success must be True regardless of what
        the caller passed (codex review #202 cycle 3)."""
        from aptl.core.lab_types import LabResult, StartupOutcome

        r = LabResult(success=False, outcome=StartupOutcome.DEGRADED_USABLE)
        assert r.success is True
        assert r.outcome is StartupOutcome.DEGRADED_USABLE

    def test_lab_result_success_false_with_degraded_unusable_is_corrected(self):
        """Same as the degraded_usable case — outcome is authoritative."""
        from aptl.core.lab_types import LabResult, StartupOutcome

        r = LabResult(success=False, outcome=StartupOutcome.DEGRADED_UNUSABLE)
        assert r.success is True
        assert r.outcome is StartupOutcome.DEGRADED_UNUSABLE


class TestStartupOutcomeDerivation:
    """Tests for the rule that maps a diagnostics list (plus a fatal-step
    short-circuit) into a StartupOutcome.

    Mapping rule (ADR-030):
      - If a fatal step short-circuited orchestration -> FAILED.
      - Else any non-info diagnostic with impact in {capability, readiness}
        -> DEGRADED_UNUSABLE.
      - Else any non-info diagnostic with impact in {cosmetic, telemetry}
        -> DEGRADED_USABLE.
      - Else READY.

    ``LabResult.success`` is True iff outcome is not FAILED.
    """

    def _diag(self, impact, severity, step="wait_for_services"):
        from aptl.core.lab_types import StartupDiagnostic

        return StartupDiagnostic(
            step=step,
            impact=impact,
            severity=severity,
            message="test diagnostic",
        )

    def test_empty_diagnostics_no_fatal_yields_ready(self):
        from aptl.core.lab_types import StartupOutcome
        from aptl.core.lab import derive_startup_outcome

        outcome = derive_startup_outcome(diagnostics=[], fatal=False)
        assert outcome is StartupOutcome.READY

    def test_only_info_diagnostics_yields_ready(self):
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity, StartupOutcome
        from aptl.core.lab import derive_startup_outcome

        outcome = derive_startup_outcome(
            diagnostics=[
                self._diag(DiagnosticImpact.COSMETIC, DiagnosticSeverity.INFO),
                self._diag(DiagnosticImpact.TELEMETRY, DiagnosticSeverity.INFO),
            ],
            fatal=False,
        )
        assert outcome is StartupOutcome.READY

    @pytest.mark.parametrize(
        "impact_name,severity_name,expected_name",
        [
            ("COSMETIC", "WARNING", "DEGRADED_USABLE"),
            ("TELEMETRY", "WARNING", "DEGRADED_USABLE"),
            ("CAPABILITY", "WARNING", "DEGRADED_UNUSABLE"),
            ("READINESS", "WARNING", "DEGRADED_UNUSABLE"),
            # ERROR severity is a stronger non-info; same outcome bucket
            # as WARNING — the difference shows up in CLI/UI rendering,
            # not in the outcome bucket.
            ("CAPABILITY", "ERROR", "DEGRADED_UNUSABLE"),
        ],
        ids=[
            "cosmetic_warning->degraded_usable",
            "telemetry_warning->degraded_usable",
            "capability_warning->degraded_unusable",
            "readiness_warning->degraded_unusable",
            "capability_error->degraded_unusable",
        ],
    )
    def test_single_diagnostic_yields_expected_outcome(
        self, impact_name, severity_name, expected_name
    ):
        """The mapping table from (impact, severity) to outcome.

        Parameterized so the table is the source of truth — adding a new
        bucket means adding one row, not copy-pasting a test method."""
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity, StartupOutcome
        from aptl.core.lab import derive_startup_outcome

        impact = DiagnosticImpact[impact_name]
        severity = DiagnosticSeverity[severity_name]
        expected = StartupOutcome[expected_name]

        outcome = derive_startup_outcome(
            diagnostics=[self._diag(impact, severity)],
            fatal=False,
        )
        assert outcome is expected

    def test_mixed_telemetry_and_capability_yields_degraded_unusable(self):
        """The most severe bucket wins."""
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity, StartupOutcome
        from aptl.core.lab import derive_startup_outcome

        outcome = derive_startup_outcome(
            diagnostics=[
                self._diag(DiagnosticImpact.TELEMETRY, DiagnosticSeverity.WARNING),
                self._diag(DiagnosticImpact.CAPABILITY, DiagnosticSeverity.WARNING),
            ],
            fatal=False,
        )
        assert outcome is StartupOutcome.DEGRADED_UNUSABLE

    def test_fatal_true_always_yields_failed(self):
        """A fatal short-circuit overrides any diagnostics — failure
        must be distinguishable from degraded_unusable per ADR-030."""
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity, StartupOutcome
        from aptl.core.lab import derive_startup_outcome

        outcome = derive_startup_outcome(
            diagnostics=[
                self._diag(DiagnosticImpact.CAPABILITY, DiagnosticSeverity.WARNING),
            ],
            fatal=True,
        )
        assert outcome is StartupOutcome.FAILED

    def test_fatal_true_with_no_diagnostics_yields_failed(self):
        from aptl.core.lab_types import StartupOutcome
        from aptl.core.lab import derive_startup_outcome

        assert derive_startup_outcome(diagnostics=[], fatal=True) is StartupOutcome.FAILED


class TestOrchestrateLabStart:
    """Tests for the full lab start orchestration."""

    def _make_env_vars(self):
        """Create a test EnvVars instance."""
        from aptl.core.env import EnvVars

        return EnvVars(
            indexer_username="admin",
            indexer_password="secret",
            api_username="wazuh-wui",
            api_password="apisecret",
            dashboard_username="kibanaserver",
            dashboard_password="kibanapass",
            wazuh_cluster_key="clusterkey",
        )

    def _make_config(self):
        """Create a test AptlConfig."""
        from aptl.core.config import AptlConfig

        return AptlConfig(
            lab={"name": "test-lab"},
            containers={"wazuh": True, "victim": True, "kali": True, "reverse": False},
        )

    def _patch_all_steps(self, mocker, tmp_path):
        """Patch all orchestration sub-functions and return mocks dict."""
        env_vars = self._make_env_vars()
        config = self._make_config()

        mocks = {}

        # .env file
        env_file = tmp_path / ".env"
        env_file.write_text(
            'INDEXER_USERNAME=admin\n'
            'INDEXER_PASSWORD=secret\n'
            'API_USERNAME=wazuh-wui\n'
            'API_PASSWORD=apisecret\n'
            'DASHBOARD_USERNAME=kibanaserver\n'
            'DASHBOARD_PASSWORD=kibanapass\n'
            'WAZUH_CLUSTER_KEY=clusterkey\n'
        )

        # aptl.json config
        import json
        config_file = tmp_path / "aptl.json"
        config_file.write_text(json.dumps({
            "lab": {"name": "test-lab"},
            "containers": {"wazuh": True, "victim": True, "kali": True, "reverse": False},
        }))

        # SSH keys dir
        keys_dir = tmp_path / "containers" / "keys"
        keys_dir.mkdir(parents=True)

        # Config dirs for credentials
        dashboard_dir = tmp_path / "config" / "wazuh_dashboard"
        dashboard_dir.mkdir(parents=True)
        (dashboard_dir / "wazuh.yml").write_text('password: "old"')

        manager_dir = tmp_path / "config" / "wazuh_cluster"
        manager_dir.mkdir(parents=True)
        (manager_dir / "wazuh_manager.conf").write_text('<key>old</key>')

        # SSL certs exist already
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)

        # MCP build script
        mcp_dir = tmp_path / "mcp"
        mcp_dir.mkdir()
        build_script = mcp_dir / "build-all-mcps.sh"
        build_script.write_text("#!/bin/bash\necho done")
        build_script.chmod(0o755)

        # Mock SSH key generation
        from aptl.core.ssh import SSHKeyResult
        mocks["ssh"] = mocker.patch(
            "aptl.core.lab.ensure_ssh_keys",
            return_value=SSHKeyResult(
                success=True,
                generated=False,
                key_path=Path.home() / ".ssh" / "aptl_lab_key",
            ),
        )

        # Mock sysreqs
        from aptl.core.sysreqs import SysReqResult
        mocks["sysreqs"] = mocker.patch(
            "aptl.core.lab.check_max_map_count",
            return_value=SysReqResult(passed=True, current_value=262144, required_value=262144),
        )

        # Mock credentials sync
        mocks["dashboard_creds"] = mocker.patch("aptl.core.lab.sync_dashboard_config")
        mocks["manager_creds"] = mocker.patch("aptl.core.lab.sync_manager_config")
        mocks["suricata_misp_rules"] = mocker.patch(
            "aptl.core.lab.sync_suricata_misp_rule_baselines"
        )

        # Mock certs
        from aptl.core.certs import CertResult
        mocks["certs"] = mocker.patch(
            "aptl.core.lab.ensure_ssl_certs",
            return_value=CertResult(success=True, generated=False, certs_dir=certs_dir),
        )

        # Mock ACES runtime handoff start
        from aptl.core.lab import LabResult
        mocks["start"] = mocker.patch(
            "aptl.core.lab.start_aces_scenario",
            return_value=LabResult(success=True, message="Lab started"),
        )

        # Mock service waiting
        from aptl.core.services import ServiceResult
        mocks["wait_indexer"] = mocker.patch(
            "aptl.core.lab.wait_for_service",
            return_value=ServiceResult(ready=True, elapsed_seconds=10.0),
        )

        # Mock snapshot capture
        from aptl.core.snapshot import RangeSnapshot
        mocks["capture_snapshot"] = mocker.patch(
            "aptl.core.lab.capture_snapshot",
            return_value=RangeSnapshot(),
        )

        # Mock MCP build subprocess
        mocks["mcp_subprocess"] = mocker.patch(
            "aptl.core.lab.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        # Mock container IP resolution for the SSH readiness step —
        # lab targets are addressed by container IP (issue #293).
        mocks["container_networks"] = mocker.patch(
            "aptl.core.lab.container_networks",
            return_value={"aptl_aptl-internal": "172.20.2.20"},
        )

        return mocks

    def test_orchestrates_all_steps_in_order(self, mocker, tmp_path):
        """Should call all orchestration steps."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True
        mocks["ssh"].assert_called_once()
        mocks["sysreqs"].assert_called_once()
        mocks["certs"].assert_called_once()
        mocks["start"].assert_called_once()
        mocks["capture_snapshot"].assert_called_once()

    def test_stops_on_env_loading_failure(self, mocker, tmp_path):
        """Should fail early if .env loading fails."""
        from aptl.core.lab import orchestrate_lab_start

        # No .env file exists
        # aptl.json still needed to not hit a different error first
        import json
        (tmp_path / "aptl.json").write_text(json.dumps({"lab": {"name": "test"}}))

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "env" in result.error.lower() or ".env" in result.error

    def test_stops_on_config_loading_failure(self, mocker, tmp_path):
        """Should fail early if config loading fails."""
        from aptl.core.lab import orchestrate_lab_start

        # .env exists but no aptl.json
        (tmp_path / ".env").write_text(
            'INDEXER_USERNAME=admin\n'
            'INDEXER_PASSWORD=secret\n'
            'API_USERNAME=wazuh-wui\n'
            'API_PASSWORD=apisecret\n'
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "config" in result.error.lower() or "aptl.json" in result.error

    def test_stops_on_sysreqs_failure(self, mocker, tmp_path):
        """Should fail if system requirements check fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.sysreqs import SysReqResult
        mocks["sysreqs"].return_value = SysReqResult(
            passed=False, current_value=65530, required_value=262144
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "map_count" in result.error.lower() or "sysreq" in result.error.lower()
        # Should not have tried to start lab
        mocks["start"].assert_not_called()

    def test_stops_on_ssh_key_generation_failure(self, mocker, tmp_path):
        """Should fail if SSH key generation fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.ssh import SSHKeyResult
        mocks["ssh"].return_value = SSHKeyResult(
            success=False, generated=False, error="Permission denied"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        # Should not proceed to sysreqs
        mocks["sysreqs"].assert_not_called()

    def test_continues_past_ssh_test_failure(self, mocker, tmp_path):
        """Should continue (with warning) when SSH connection test fails."""
        from aptl.core.lab import orchestrate_lab_start
        from aptl.core.services import ServiceResult

        mocks = self._patch_all_steps(mocker, tmp_path)
        # wait_for_service is used for indexer, manager, and now SSH —
        # return not-ready to simulate SSH timeout
        mocks["wait_indexer"].return_value = ServiceResult(
            ready=False, elapsed_seconds=60.0, error="SSH timed out"
        )

        result = orchestrate_lab_start(tmp_path)

        # Overall should still succeed (SSH/service waits are non-critical)
        assert result.success is True
        mocks["capture_snapshot"].assert_called_once()

    def test_continues_past_mcp_build_failure(self, mocker, tmp_path):
        """Should continue (with warning) when MCP build fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)
        mocks["mcp_subprocess"].return_value = MagicMock(
            returncode=1, stdout="", stderr="npm error"
        )

        result = orchestrate_lab_start(tmp_path)

        # Overall should still succeed
        assert result.success is True

    def test_passes_env_data_to_credentials_sync(self, mocker, tmp_path):
        """Should pass correct env values to credential sync functions."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        orchestrate_lab_start(tmp_path)

        # Dashboard config should be called with API password
        mocks["dashboard_creds"].assert_called_once()
        call_args = mocks["dashboard_creds"].call_args
        assert call_args[0][1] == "apisecret"

        # Manager config should be called with cluster key
        mocks["manager_creds"].assert_called_once()
        call_args = mocks["manager_creds"].call_args
        assert call_args[0][1] == "clusterkey"

        mocks["suricata_misp_rules"].assert_called_once_with(tmp_path)

    def test_stops_on_cert_generation_failure(self, mocker, tmp_path):
        """Should fail if certificate generation fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.certs import CertResult
        mocks["certs"].return_value = CertResult(
            success=False, generated=False, error="docker not found"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        mocks["start"].assert_not_called()

    def test_stops_on_docker_compose_start_failure(self, mocker, tmp_path):
        """Should fail if docker compose up fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.lab import LabResult
        mocks["start"].return_value = LabResult(
            success=False, error="compose up failed"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        mocks["capture_snapshot"].assert_not_called()

    def test_aborts_when_credential_render_fails(self, mocker, tmp_path):
        """A credential-render failure aborts lab start (ADR-028).

        The rendered ``.aptl/config/...`` files are mandatory Docker
        Compose bind-mount sources, so a failed render must stop startup
        rather than let the lab come up with stale/absent credential
        config from a previous run.
        """
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)
        mocks["dashboard_creds"].side_effect = RuntimeError("render failed")

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "render" in (result.error or "").lower()
        # Containers must not start after a failed render.
        mocks["start"].assert_not_called()

    def test_aborts_when_suricata_misp_rule_seed_fails(self, mocker, tmp_path):
        """MISP rule baselines are mandatory bind-mount sources under .aptl/."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)
        mocks["suricata_misp_rules"].side_effect = RuntimeError("seed failed")

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "suricata misp" in (result.error or "").lower()
        mocks["certs"].assert_not_called()
        mocks["start"].assert_not_called()

    def test_handles_empty_profiles(self, mocker, tmp_path):
        """Should work when all containers are disabled (C6)."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        # Override config to disable all containers
        import json
        config_file = tmp_path / "aptl.json"
        config_file.write_text(json.dumps({
            "lab": {"name": "test-lab"},
            "containers": {"wazuh": False, "victim": False, "kali": False, "reverse": False},
        }))

        # Re-mock ACES handoff and wait_for_service since config changes
        from aptl.core.lab import LabResult
        mocks["start"].return_value = LabResult(success=True, message="Lab started")

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True

    def test_fails_on_nonexistent_project_dir(self, mocker, tmp_path):
        """Should fail when project_dir does not exist (C6)."""
        from aptl.core.lab import orchestrate_lab_start

        nonexistent = tmp_path / "does_not_exist"

        result = orchestrate_lab_start(nonexistent)

        assert result.success is False

    def test_pre_pull_runs_before_compose_up(self, mocker, tmp_path):
        """Should call docker pull for images before compose up."""
        from aptl.core.lab import (
            _LAB_START_STEPS,
            _step_pull_images,
            _step_start_containers,
            orchestrate_lab_start,
        )

        mocks = self._patch_all_steps(mocker, tmp_path)

        step_names = [step.__name__ for step in _LAB_START_STEPS]
        assert step_names.index(_step_pull_images.__name__) < step_names.index(
            _step_start_containers.__name__
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True
        # The mcp_subprocess mock also catches the docker pull calls
        pull_calls = [
            c for c in mocks["mcp_subprocess"].call_args_list
            if len(c[0]) > 0 and len(c[0][0]) > 1 and c[0][0][0] == "docker" and c[0][0][1] == "pull"
        ]
        assert len(pull_calls) >= 1


class TestSyncCredentialsStep:
    """Direct tests for `_step_sync_credentials` (issue #266 follow-up).

    Distinguishes ordinary sync failures (FileNotFoundError, regex
    no-match, write errors) — which stay non-fatal warnings — from
    path-containment ``ValueError`` raised by ``_resolve_within_project``,
    which is a security guardrail breach and must fail orchestration.
    """

    def _ctx(self, mocker, tmp_path):
        from aptl.core.env import EnvVars
        from aptl.core.lab import _LabStartContext

        # `backend` is required by the issue #214 runtime contract on
        # `_step_sync_credentials`; supply a stub so the contract is
        # satisfied without affecting the local-render path under test.
        return _LabStartContext(
            project_dir=tmp_path,
            skip_seed=False,
            env=EnvVars(
                indexer_username="x", indexer_password="x",
                api_username="x", api_password="api_pw",
                wazuh_cluster_key="cluster_key",
            ),
            backend=MagicMock(),
        )

    def test_dashboard_containment_breach_fails_lab_start(self, mocker, tmp_path):
        """A PathContainmentError from sync_dashboard_config aborts the step."""
        from aptl.core.credentials import PathContainmentError
        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(mocker, tmp_path)
        mocker.patch(
            "aptl.core.lab.sync_dashboard_config",
            side_effect=PathContainmentError(
                "Resolved config path /etc/passwd escapes project root /tmp/x"
            ),
        )
        manager_mock = mocker.patch("aptl.core.lab.sync_manager_config")

        result = _step_sync_credentials(ctx)

        assert result is not None
        assert result.success is False
        assert "escapes project root" in (result.error or "")
        # Manager sync must not run after a guardrail breach.
        manager_mock.assert_not_called()

    def test_manager_containment_breach_fails_lab_start(self, mocker, tmp_path):
        """A PathContainmentError from sync_manager_config aborts the step."""
        from aptl.core.credentials import PathContainmentError
        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(mocker, tmp_path)
        mocker.patch("aptl.core.lab.sync_dashboard_config")
        mocker.patch(
            "aptl.core.lab.sync_manager_config",
            side_effect=PathContainmentError(
                "Resolved config path /etc/something escapes project root /tmp/x"
            ),
        )

        result = _step_sync_credentials(ctx)

        assert result is not None
        assert result.success is False
        assert "escapes project root" in (result.error or "")

    def test_missing_template_aborts_lab_start(self, mocker, tmp_path):
        """A FileNotFoundError (missing source template) aborts lab start.

        The rendered file is a mandatory Compose mount source (ADR-028):
        if it can't be produced, the lab must not come up with a stale
        copy from a previous run.
        """
        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(mocker, tmp_path)
        mocker.patch(
            "aptl.core.lab.sync_dashboard_config",
            side_effect=FileNotFoundError("config template not found"),
        )
        manager_mock = mocker.patch("aptl.core.lab.sync_manager_config")

        result = _step_sync_credentials(ctx)

        assert result is not None
        assert result.success is False
        assert "render" in (result.error or "").lower()
        # The breach message must not be misclassified as a containment one.
        assert "escapes project root" not in (result.error or "")
        manager_mock.assert_not_called()

    def test_bare_value_error_aborts_lab_start(self, mocker, tmp_path):
        """A ValueError that is *not* PathContainmentError still aborts, but
        is reported as a generic render failure, not a containment breach."""
        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(mocker, tmp_path)
        mocker.patch(
            "aptl.core.lab.sync_dashboard_config",
            side_effect=ValueError("regex parse failed: invalid escape"),
        )
        mocker.patch("aptl.core.lab.sync_manager_config")

        result = _step_sync_credentials(ctx)

        assert result is not None
        assert result.success is False
        assert "escapes project root" not in (result.error or "")

    def test_disk_error_aborts_lab_start(self, mocker, tmp_path):
        """An OSError from the renderer (e.g. a directory sitting at the
        rendered-output path) aborts lab start."""
        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(mocker, tmp_path)
        mocker.patch("aptl.core.lab.sync_dashboard_config")
        mocker.patch(
            "aptl.core.lab.sync_manager_config",
            side_effect=OSError("Is a directory"),
        )

        result = _step_sync_credentials(ctx)

        assert result is not None
        assert result.success is False

    def test_ssh_remote_backend_aborts_render(self, mocker, tmp_path):
        """Rendering credentialized config when the deployment backend
        targets a remote Docker daemon would leave the remote bind mounts
        pointing at nothing — refuse rather than ship a broken lab."""
        from aptl.core.deployment import SSHComposeBackend
        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(mocker, tmp_path)
        ctx.backend = SSHComposeBackend(tmp_path, host="lab.example.com", user="deploy")
        dashboard_mock = mocker.patch("aptl.core.lab.sync_dashboard_config")
        manager_mock = mocker.patch("aptl.core.lab.sync_manager_config")

        result = _step_sync_credentials(ctx)

        assert result is not None
        assert result.success is False
        assert "deployment host" in (result.error or "")
        # Neither writer should have run.
        dashboard_mock.assert_not_called()
        manager_mock.assert_not_called()

    def test_happy_path_returns_none(self, mocker, tmp_path):
        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(mocker, tmp_path)
        mocker.patch("aptl.core.lab.sync_dashboard_config")
        mocker.patch("aptl.core.lab.sync_manager_config")

        result = _step_sync_credentials(ctx)

        assert result is None

    def test_renders_to_aptl_config_and_leaves_source_untouched(self, mocker, tmp_path):
        """End-to-end (real credential writers): the step renders the
        credentialized copies under ``.aptl/config/`` and never mutates the
        checked-in ``config/`` templates (ADR-028 / issue #200)."""
        from aptl.core.lab import _step_sync_credentials

        dashboard_src = tmp_path / "config" / "wazuh_dashboard" / "wazuh.yml"
        dashboard_src.parent.mkdir(parents=True)
        dashboard_src.write_text('      password: "TEMPLATE_PW"\n')
        manager_src = tmp_path / "config" / "wazuh_cluster" / "wazuh_manager.conf"
        manager_src.parent.mkdir(parents=True)
        manager_src.write_text("<cluster>\n  <key>TEMPLATE_KEY</key>\n</cluster>\n")

        dashboard_before = dashboard_src.read_bytes()
        manager_before = manager_src.read_bytes()

        ctx = self._ctx(mocker, tmp_path)  # env has api_password="api_pw", cluster_key="cluster_key"

        result = _step_sync_credentials(ctx)

        assert result is None
        # Source templates byte-for-byte unchanged.
        assert dashboard_src.read_bytes() == dashboard_before
        assert manager_src.read_bytes() == manager_before
        # Rendered copies exist under .aptl/config/ with the real secrets.
        rendered_dashboard = tmp_path / ".aptl" / "config" / "wazuh_dashboard" / "wazuh.yml"
        rendered_manager = tmp_path / ".aptl" / "config" / "wazuh_cluster" / "wazuh_manager.conf"
        assert 'password: "api_pw"' in rendered_dashboard.read_text()
        assert "<key>cluster_key</key>" in rendered_manager.read_text()


class TestSyncSuricataMispRuleBaselinesStep:
    """Direct tests for ADR-028 Suricata MISP rule baseline seeding."""

    def _ctx(self, tmp_path):
        from aptl.core.lab import _LabStartContext

        # `backend` is required by the issue #214 runtime contract on
        # `_step_sync_suricata_misp_rule_baselines`; supply a stub so
        # the local-render path under test is reachable.
        return _LabStartContext(
            project_dir=tmp_path,
            skip_seed=False,
            backend=MagicMock(),
        )

    def test_seeds_to_aptl_tree_and_leaves_source_untouched(self, tmp_path):
        from aptl.core.lab import _step_sync_suricata_misp_rule_baselines

        source_dir = tmp_path / "config" / "suricata" / "rules" / "misp"
        source_dir.mkdir(parents=True)
        baselines = {
            "misp-iocs.rules": "# baseline rules\n",
            "misp-md5.list": "# md5 baseline\n",
            "misp-sha1.list": "# sha1 baseline\n",
            "misp-sha256.list": "# sha256 baseline\n",
        }
        for name, content in baselines.items():
            (source_dir / name).write_text(content)
        before = {path.name: path.read_bytes() for path in source_dir.iterdir()}

        result = _step_sync_suricata_misp_rule_baselines(self._ctx(tmp_path))

        assert result is None
        assert {path.name: path.read_bytes() for path in source_dir.iterdir()} == before
        generated_dir = tmp_path / ".aptl" / "suricata" / "rules" / "misp"
        for name, content in baselines.items():
            assert (generated_dir / name).read_text() == content

    def test_seed_error_aborts_lab_start_step(self, mocker, tmp_path):
        from aptl.core.lab import _step_sync_suricata_misp_rule_baselines

        ctx = self._ctx(tmp_path)
        mocker.patch(
            "aptl.core.lab.sync_suricata_misp_rule_baselines",
            side_effect=FileNotFoundError("missing baseline"),
        )

        result = _step_sync_suricata_misp_rule_baselines(ctx)

        assert result is not None
        assert result.success is False
        assert "suricata misp" in (result.error or "").lower()


class TestStartupClassificationWiring:
    """Per-step assertions that each non-critical failure path produces
    the expected structured diagnostic (ADR-030).

    These tests drive individual ``_step_*`` functions against a
    ``_LabStartContext`` with the right pre-conditions, then read the
    diagnostics that were appended. They are deliberately step-scoped
    so the assertions stay narrow and the mocks stay small.
    """

    def _make_env_vars(self):
        from aptl.core.env import EnvVars

        return EnvVars(
            indexer_username="admin",
            indexer_password="secret",
            api_username="wazuh-wui",
            api_password="apisecret",
            dashboard_username="kibanaserver",
            dashboard_password="kibanapass",
            wazuh_cluster_key="clusterkey",
        )

    def _make_config(self, *, victim=True, kali=True, reverse=True, wazuh=True):
        from aptl.core.config import AptlConfig

        return AptlConfig(
            lab={"name": "test-lab"},
            containers={
                "wazuh": wazuh,
                "victim": victim,
                "kali": kali,
                "reverse": reverse,
            },
        )

    def _ctx(self, tmp_path, *, config=None):
        from aptl.core.lab import _LabStartContext

        return _LabStartContext(
            project_dir=tmp_path,
            skip_seed=False,
            env=self._make_env_vars(),
            config=config or self._make_config(),
            ssh_key_path=Path("/tmp/aptl_lab_key"),
            backend=MagicMock(),
        )

    # -- redaction at the diagnostic boundary --------------------------

    def test_emit_diagnostic_redacts_credential_shaped_message(self, tmp_path):
        """_emit_diagnostic is the choke point for everything that crosses
        the CLI/API/web boundary — callers must not be able to leak a
        credential-shaped payload through it even by accident.

        Codex review (cycle 2) flagged the bare-message path as the
        regression-prone seam; the helper now applies the same
        ``aptl.utils.redaction.redact()`` boundary used by snapshot/run
        archives (ADR-029)."""
        from aptl.core.lab import _emit_diagnostic
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(tmp_path)
        _emit_diagnostic(
            ctx,
            step="future_step_that_forgot",
            impact=DiagnosticImpact.CAPABILITY,
            severity=DiagnosticSeverity.WARNING,
            message="API_KEY=hunter2 leaked into a future caller's text",
            operator_action="Bearer abcd1234deadbeef token in operator note",
        )

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert "hunter2" not in diag.message
        assert "[REDACTED]" in diag.message
        assert "abcd1234deadbeef" not in diag.operator_action
        # Narrow internal identifiers like the step name must remain
        # intact so the diagnostic stays attributable.
        assert diag.step == "future_step_that_forgot"

    # -- pull_images (cosmetic) ----------------------------------------

    def test_pull_images_clean_emits_no_diagnostic(self, tmp_path):
        from aptl.core.lab import _step_pull_images

        ctx = self._ctx(tmp_path)
        backend = MagicMock()
        backend.pull_images.return_value = []
        ctx.backend = backend

        _step_pull_images(ctx)

        assert ctx.diagnostics == []

    def test_pull_images_warnings_emit_cosmetic_info(self, tmp_path):
        from aptl.core.lab import _step_pull_images
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(tmp_path)
        backend = MagicMock()
        backend.pull_images.return_value = [
            "Failed to pull wazuh/wazuh-manager:4.12.0: connection reset",
            "Failed to pull wazuh/wazuh-dashboard:4.12.0: rate limit",
        ]
        ctx.backend = backend

        _step_pull_images(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "pull_images"
        assert diag.impact is DiagnosticImpact.COSMETIC
        assert diag.severity is DiagnosticSeverity.INFO
        # ADR-030 guardrail: do not embed raw subprocess stderr in the
        # structured message. The diagnostic carries a narrow summary.
        assert "connection reset" not in diag.message
        assert "rate limit" not in diag.message
        assert "2" in diag.message  # number of failed images

    # -- wait_for_services (telemetry) ---------------------------------

    def test_wait_for_services_indexer_timeout_emits_telemetry_warning(
        self, tmp_path, mocker
    ):
        from aptl.core.lab import _step_wait_for_services
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity
        from aptl.core.services import ServiceResult

        ctx = self._ctx(tmp_path)
        # Indexer not ready, Manager ready
        mocker.patch(
            "aptl.core.lab.wait_for_service",
            side_effect=[
                ServiceResult(ready=False, elapsed_seconds=300.0, error="timed out"),
                ServiceResult(ready=True, elapsed_seconds=12.0),
            ],
        )

        _step_wait_for_services(ctx)

        indexer_diags = [d for d in ctx.diagnostics if d.component == "wazuh_indexer"]
        assert len(indexer_diags) == 1
        assert indexer_diags[0].impact is DiagnosticImpact.TELEMETRY
        assert indexer_diags[0].severity is DiagnosticSeverity.WARNING
        assert indexer_diags[0].step == "wait_for_services"
        manager_diags = [d for d in ctx.diagnostics if d.component == "wazuh_manager"]
        assert manager_diags == []

    def test_wait_for_services_manager_timeout_emits_telemetry_warning(
        self, tmp_path, mocker
    ):
        from aptl.core.lab import _step_wait_for_services
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity
        from aptl.core.services import ServiceResult

        ctx = self._ctx(tmp_path)
        mocker.patch(
            "aptl.core.lab.wait_for_service",
            side_effect=[
                ServiceResult(ready=True, elapsed_seconds=12.0),
                ServiceResult(ready=False, elapsed_seconds=120.0, error="timed out"),
            ],
        )

        _step_wait_for_services(ctx)

        manager_diags = [d for d in ctx.diagnostics if d.component == "wazuh_manager"]
        assert len(manager_diags) == 1
        assert manager_diags[0].impact is DiagnosticImpact.TELEMETRY
        assert manager_diags[0].severity is DiagnosticSeverity.WARNING

    def test_wait_for_services_clean_emits_no_diagnostic(self, tmp_path, mocker):
        from aptl.core.lab import _step_wait_for_services
        from aptl.core.services import ServiceResult

        ctx = self._ctx(tmp_path)
        mocker.patch(
            "aptl.core.lab.wait_for_service",
            return_value=ServiceResult(ready=True, elapsed_seconds=10.0),
        )

        _step_wait_for_services(ctx)

        assert ctx.diagnostics == []

    def test_wait_for_services_skipped_when_wazuh_disabled(self, tmp_path, mocker):
        from aptl.core.lab import _step_wait_for_services
        from aptl.core.services import ServiceResult

        ctx = self._ctx(tmp_path, config=self._make_config(wazuh=False))
        wait_mock = mocker.patch(
            "aptl.core.lab.wait_for_service",
            return_value=ServiceResult(ready=False, elapsed_seconds=300.0, error="timed out"),
        )

        _step_wait_for_services(ctx)

        # Wazuh probes never ran -> no diagnostics.
        assert ctx.diagnostics == []
        wait_mock.assert_not_called()

    # -- test_ssh (readiness) ------------------------------------------

    def test_test_ssh_per_target_timeout_emits_readiness_warning(
        self, tmp_path, mocker
    ):
        from aptl.core.lab import _step_test_ssh
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity
        from aptl.core.services import ServiceResult

        ctx = self._ctx(tmp_path)
        # Targets are addressed by container IP (issue #293), not a
        # published host port — resolve a stub IP for every target.
        mocker.patch(
            "aptl.core.lab.container_networks",
            return_value={"aptl_aptl-internal": "172.20.2.20"},
        )
        # victim ready, kali timeout, reverse ready
        mocker.patch(
            "aptl.core.lab.wait_for_service",
            side_effect=[
                ServiceResult(ready=True, elapsed_seconds=2.0),
                ServiceResult(ready=False, elapsed_seconds=60.0, error="timed out"),
                ServiceResult(ready=True, elapsed_seconds=3.0),
            ],
        )

        _step_test_ssh(ctx)

        readiness_diags = [
            d for d in ctx.diagnostics if d.impact is DiagnosticImpact.READINESS
        ]
        assert len(readiness_diags) == 1
        diag = readiness_diags[0]
        assert diag.step == "test_ssh"
        assert diag.component == "ssh:kali"
        assert diag.severity is DiagnosticSeverity.WARNING

    def test_test_ssh_probes_container_ip_on_port_22(self, tmp_path, mocker):
        # Regression for issue #293: the SSH probe must target the
        # container IP on port 22, not localhost on a (never-published)
        # remapped host port.
        from aptl.core.lab import _step_test_ssh
        from aptl.core.services import ServiceResult

        ctx = self._ctx(tmp_path)
        mocker.patch(
            "aptl.core.lab.container_networks",
            return_value={"aptl_aptl-redteam": "172.20.4.30"},
        )
        wait = mocker.patch(
            "aptl.core.lab.wait_for_service",
            return_value=ServiceResult(ready=True, elapsed_seconds=1.0),
        )

        _step_test_ssh(ctx)

        # Inspect the partial passed to wait_for_service for the SSH probe.
        for call in wait.call_args_list:
            check_fn = call.kwargs["check_fn"]
            assert check_fn.keywords["host"] == "172.20.4.30"
            assert check_fn.keywords["port"] == 22

    def test_test_ssh_unresolvable_ip_emits_readiness_warning(
        self, tmp_path, mocker
    ):
        # A target whose container has no resolvable network IP cannot
        # be probed — surface it as a readiness diagnostic rather than
        # silently skipping (issue #293).
        from aptl.core.lab import _step_test_ssh
        from aptl.core.lab_types import DiagnosticImpact

        ctx = self._ctx(tmp_path)
        mocker.patch("aptl.core.lab.container_networks", return_value={})
        wait = mocker.patch("aptl.core.lab.wait_for_service")

        _step_test_ssh(ctx)

        readiness_diags = [
            d for d in ctx.diagnostics if d.impact is DiagnosticImpact.READINESS
        ]
        assert {d.component for d in readiness_diags} >= {"ssh:kali"}
        assert all("no resolvable network IP" in d.message for d in readiness_diags)
        # No SSH probe is attempted when the IP cannot be resolved.
        wait.assert_not_called()

    def test_test_ssh_all_ready_emits_no_diagnostic(self, tmp_path, mocker):
        from aptl.core.lab import _step_test_ssh
        from aptl.core.services import ServiceResult

        ctx = self._ctx(tmp_path)
        mocker.patch(
            "aptl.core.lab.container_networks",
            return_value={"aptl_aptl-internal": "172.20.2.20"},
        )
        mocker.patch(
            "aptl.core.lab.wait_for_service",
            return_value=ServiceResult(ready=True, elapsed_seconds=2.0),
        )

        _step_test_ssh(ctx)

        assert ctx.diagnostics == []

    # -- build_mcps (capability) ---------------------------------------

    def test_build_mcps_missing_script_emits_capability_warning(self, tmp_path):
        from aptl.core.lab import _step_build_mcps
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(tmp_path)
        # No mcp/build-all-mcps.sh script in tmp_path
        _step_build_mcps(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "build_mcps"
        assert diag.impact is DiagnosticImpact.CAPABILITY
        assert diag.severity is DiagnosticSeverity.WARNING
        assert "script" in diag.message.lower()

    def test_build_mcps_nonzero_exit_emits_capability_warning(
        self, tmp_path, mocker
    ):
        from aptl.core.lab import _step_build_mcps
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(tmp_path)
        # Create the script so we get past the existence check
        mcp_dir = tmp_path / "mcp"
        mcp_dir.mkdir()
        (mcp_dir / "build-all-mcps.sh").write_text("#!/bin/bash\nexit 1\n")
        (mcp_dir / "build-all-mcps.sh").chmod(0o755)

        mocker.patch(
            "aptl.core.lab.subprocess.run",
            return_value=MagicMock(
                returncode=1,
                stdout="",
                stderr="npm error: TOKEN=abcdef-leak-shaped-text",
            ),
        )

        _step_build_mcps(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.impact is DiagnosticImpact.CAPABILITY
        assert diag.severity is DiagnosticSeverity.WARNING
        # ADR-030 / ADR-029: stderr must not appear in the structured
        # diagnostic message.
        assert "abcdef-leak-shaped-text" not in diag.message
        assert "TOKEN=" not in diag.message

    def test_build_mcps_clean_emits_no_diagnostic(self, tmp_path, mocker):
        from aptl.core.lab import _step_build_mcps

        ctx = self._ctx(tmp_path)
        mcp_dir = tmp_path / "mcp"
        mcp_dir.mkdir()
        (mcp_dir / "build-all-mcps.sh").write_text("#!/bin/bash\necho done\n")
        (mcp_dir / "build-all-mcps.sh").chmod(0o755)

        mocker.patch(
            "aptl.core.lab.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        _step_build_mcps(ctx)

        assert ctx.diagnostics == []

    # -- capture_snapshot (telemetry) ----------------------------------

    def test_capture_snapshot_clean_emits_no_diagnostic(self, tmp_path, mocker):
        from aptl.core.lab import _step_capture_snapshot
        from aptl.core.snapshot import RangeSnapshot

        ctx = self._ctx(tmp_path)
        ctx.backend = MagicMock()
        mocker.patch(
            "aptl.core.lab.capture_snapshot", return_value=RangeSnapshot()
        )

        _step_capture_snapshot(ctx)

        assert ctx.diagnostics == []

    def test_capture_snapshot_failure_emits_telemetry_warning(
        self, tmp_path, mocker
    ):
        """Snapshot is the run-archive inventory — its loss is observability
        debt, not a hard failure. ADR-030 lists snapshot capture among the
        late startup checks that must surface as structured diagnostics."""
        from aptl.core.lab import _step_capture_snapshot
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(tmp_path)
        ctx.backend = MagicMock()
        mocker.patch(
            "aptl.core.lab.capture_snapshot",
            side_effect=RuntimeError("docker daemon unreachable"),
        )

        # Must not raise — degradation, not failure.
        _step_capture_snapshot(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "capture_snapshot"
        assert diag.impact is DiagnosticImpact.TELEMETRY
        assert diag.severity is DiagnosticSeverity.WARNING
        # Exception text must not leak into the structured message
        # (ADR-029 / ADR-030).
        assert "docker daemon unreachable" not in diag.message

    # -- seed_soc (capability) -----------------------------------------

    def test_seed_soc_nonzero_exit_emits_capability_warning(self, tmp_path, mocker):
        from aptl.core.config import AptlConfig
        from aptl.core.lab import _step_seed_soc
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(
            tmp_path,
            # Full prime profile set so issue #214's required-profiles
            # contract on `_seed_prime_soc` is satisfied; this test
            # exercises the subprocess-failure path, not the gating.
            config=AptlConfig(
                lab={"name": "test-lab"},
                containers={
                    "wazuh": True,
                    "enterprise": True,
                    "victim": True,
                    "kali": True,
                    "fileshare": True,
                    "soc": True,
                },
            ),
        )
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        seed_script = scripts_dir / "seed-prime.sh"
        seed_script.write_text("#!/bin/bash\nexit 1\n")
        seed_script.chmod(0o755)

        mocker.patch(
            "aptl.core.lab.subprocess.run",
            return_value=MagicMock(
                returncode=1,
                stdout="",
                stderr="MISP_API_KEY=should-not-appear-in-diag",
            ),
        )

        _step_seed_soc(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "seed_soc"
        assert diag.impact is DiagnosticImpact.CAPABILITY
        assert diag.severity is DiagnosticSeverity.WARNING
        assert "should-not-appear-in-diag" not in diag.message

    def test_seed_soc_timeout_emits_capability_warning(self, tmp_path, mocker):
        import subprocess

        from aptl.core.config import AptlConfig
        from aptl.core.lab import _step_seed_soc
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(
            tmp_path,
            config=AptlConfig(
                lab={"name": "test-lab"},
                containers={
                    "wazuh": True,
                    "enterprise": True,
                    "victim": True,
                    "kali": True,
                    "fileshare": True,
                    "soc": True,
                },
            ),
        )
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        seed_script = scripts_dir / "seed-prime.sh"
        seed_script.write_text("#!/bin/bash\nsleep 30\n")
        seed_script.chmod(0o755)

        mocker.patch(
            "aptl.core.lab.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=str(seed_script), timeout=1),
        )

        _step_seed_soc(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "seed_soc"
        assert diag.impact is DiagnosticImpact.CAPABILITY
        assert diag.severity is DiagnosticSeverity.WARNING
        assert "timed out" in diag.message.lower() or "timeout" in diag.message.lower()

    def test_seed_soc_skipped_emits_no_diagnostic(self, tmp_path):
        """--skip-seed is an operator choice, not a degradation."""
        from aptl.core.lab import _step_seed_soc

        ctx = self._ctx(tmp_path)
        ctx.skip_seed = True

        _step_seed_soc(ctx)

        assert ctx.diagnostics == []

    def test_seed_soc_missing_script_with_soc_enabled_emits_capability_warning(
        self, tmp_path
    ):
        """SOC enabled but seed-prime.sh missing: lab will come up with empty
        SOC tools. Codex review (cycle 1) flagged the silent-skip path."""
        from aptl.core.config import AptlConfig
        from aptl.core.lab import _step_seed_soc
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(
            tmp_path,
            config=AptlConfig(
                lab={"name": "test-lab"},
                containers={
                    "wazuh": True,
                    "enterprise": True,
                    "victim": True,
                    "kali": True,
                    "fileshare": True,
                    "soc": True,
                },
            ),
        )
        # No scripts/seed-prime.sh in tmp_path
        _step_seed_soc(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "seed_soc"
        assert diag.impact is DiagnosticImpact.CAPABILITY
        assert diag.severity is DiagnosticSeverity.WARNING

    def test_seed_soc_missing_script_with_soc_disabled_emits_no_diagnostic(
        self, tmp_path
    ):
        """SOC disabled and no seed script: still a no-op, no degradation."""
        from aptl.core.lab import _step_seed_soc

        ctx = self._ctx(tmp_path, config=self._make_config())  # soc not set -> False
        # No scripts/seed-prime.sh in tmp_path
        _step_seed_soc(ctx)

        assert ctx.diagnostics == []

    # -- mcp_config_sync (capability) ----------------------------------

    def test_mcp_config_sync_exception_emits_capability_warning(
        self, tmp_path, mocker
    ):
        from aptl.core.lab import _step_sync_mcp_config
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(tmp_path)
        mocker.patch(
            "aptl.core.lab._sync_mcp_config_keys",
            side_effect=RuntimeError("THEHIVE_API_KEY mismatch"),
        )

        _step_sync_mcp_config(ctx)

        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "mcp_config_sync"
        assert diag.impact is DiagnosticImpact.CAPABILITY
        assert diag.severity is DiagnosticSeverity.WARNING
        # Exception text contains a sensitive-looking key name —
        # diagnostic message must not echo the raw exception payload.
        assert "THEHIVE_API_KEY" not in diag.message

    def test_mcp_config_sync_clean_emits_no_diagnostic(self, tmp_path, mocker):
        from aptl.core.lab import _step_sync_mcp_config

        ctx = self._ctx(tmp_path)
        mocker.patch("aptl.core.lab._sync_mcp_config_keys", return_value=None)

        _step_sync_mcp_config(ctx)

        assert ctx.diagnostics == []


class TestOrchestrateLabStartOutcome:
    """End-to-end checks that ``orchestrate_lab_start`` returns a
    ``LabResult`` whose ``outcome`` and ``diagnostics`` fields reflect
    what happened during the run (ADR-030).
    """

    def _patch_happy(self, mocker, tmp_path):
        # Reuse the same patcher TestOrchestrateLabStart uses, by
        # constructing one and borrowing its method.
        return TestOrchestrateLabStart()._patch_all_steps(mocker, tmp_path)

    def test_happy_path_yields_ready_and_empty_diagnostics(self, mocker, tmp_path):
        from aptl.core.lab import orchestrate_lab_start
        from aptl.core.lab_types import StartupOutcome

        self._patch_happy(mocker, tmp_path)

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True
        assert result.outcome is StartupOutcome.READY
        assert result.diagnostics == []

    def test_ssh_probe_timeout_yields_degraded_unusable(self, mocker, tmp_path):
        from aptl.core.lab import orchestrate_lab_start
        from aptl.core.lab_types import DiagnosticImpact, StartupOutcome
        from aptl.core.services import ServiceResult

        mocks = self._patch_happy(mocker, tmp_path)
        # Make every wait_for_service call time out — covers indexer,
        # manager, and every SSH probe.
        mocks["wait_indexer"].return_value = ServiceResult(
            ready=False, elapsed_seconds=60.0, error="timed out"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True  # back-compat: non-fatal warnings
        assert result.outcome is StartupOutcome.DEGRADED_UNUSABLE
        # At least one readiness diagnostic and one telemetry diagnostic.
        impacts = {d.impact for d in result.diagnostics}
        assert DiagnosticImpact.READINESS in impacts
        assert DiagnosticImpact.TELEMETRY in impacts

    def test_mcp_build_failure_yields_degraded_unusable(self, mocker, tmp_path):
        from aptl.core.lab import orchestrate_lab_start
        from aptl.core.lab_types import DiagnosticImpact, StartupOutcome

        mocks = self._patch_happy(mocker, tmp_path)
        mocks["mcp_subprocess"].return_value = MagicMock(
            returncode=1, stdout="", stderr="npm error"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True
        assert result.outcome is StartupOutcome.DEGRADED_UNUSABLE
        cap = [d for d in result.diagnostics if d.impact is DiagnosticImpact.CAPABILITY]
        assert any(d.step == "build_mcps" for d in cap)

    def test_fatal_step_yields_failed_outcome(self, mocker, tmp_path):
        from aptl.core.lab import LabResult, orchestrate_lab_start
        from aptl.core.lab_types import StartupOutcome

        mocks = self._patch_happy(mocker, tmp_path)
        mocks["start"].return_value = LabResult(
            success=False, error="compose up failed"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert result.outcome is StartupOutcome.FAILED


class TestLabOrchestrationContracts:
    """Runtime `icontract` preconditions on `_LabStartContext` consumers
    and `start_lab`. These replace the old `assert ctx.<field> is not None`
    guards (which were no-ops under `python -O`) per ADR-031 / issue #214.

    Each test calls the step (or `start_lab`) directly with the relevant
    field unset and confirms an `icontract.ViolationError` is raised at
    the decorator boundary — proof that the contract is in fact runtime,
    not an `assert`.
    """

    def _ctx(self, tmp_path: Path):
        from aptl.core.lab import _LabStartContext

        return _LabStartContext(project_dir=tmp_path, skip_seed=False)

    def _full_env(self):
        from aptl.core.env import EnvVars

        return EnvVars(
            indexer_username="u",
            indexer_password="p",
            api_username="u",
            api_password="p",
            wazuh_cluster_key="ck",
        )

    def _full_config(self, **container_overrides):
        from aptl.core.config import AptlConfig

        defaults = {"wazuh": True, "victim": True, "kali": True}
        defaults.update(container_overrides)
        return AptlConfig(
            lab={"name": "test-lab"}, containers=defaults
        )

    # -- env_is_loaded ------------------------------------------------

    def test_sync_credentials_without_env_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(tmp_path)  # env stays None
        with pytest.raises(icontract.ViolationError):
            _step_sync_credentials(ctx)

    def test_wait_for_services_without_env_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_wait_for_services

        ctx = self._ctx(tmp_path)
        ctx.config = self._full_config()
        # env intentionally None
        with pytest.raises(icontract.ViolationError):
            _step_wait_for_services(ctx)

    # -- config_is_loaded --------------------------------------------

    def test_start_containers_without_config_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_start_containers

        ctx = self._ctx(tmp_path)
        ctx.backend = MagicMock()
        # config stays None
        with pytest.raises(icontract.ViolationError):
            _step_start_containers(ctx)

    def test_wait_for_services_without_config_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_wait_for_services

        ctx = self._ctx(tmp_path)
        ctx.env = self._full_env()
        # config stays None
        with pytest.raises(icontract.ViolationError):
            _step_wait_for_services(ctx)

    def test_test_ssh_without_config_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_test_ssh

        ctx = self._ctx(tmp_path)
        ctx.ssh_key_path = Path("/tmp/aptl_lab_key")
        # config stays None
        with pytest.raises(icontract.ViolationError):
            _step_test_ssh(ctx)

    def test_seed_soc_without_config_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_seed_soc

        ctx = self._ctx(tmp_path)
        # config stays None
        with pytest.raises(icontract.ViolationError):
            _step_seed_soc(ctx)

    # -- backend_is_initialized --------------------------------------

    def test_pull_images_without_backend_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_pull_images

        ctx = self._ctx(tmp_path)
        # backend stays None
        with pytest.raises(icontract.ViolationError):
            _step_pull_images(ctx)

    def test_start_containers_without_backend_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_start_containers

        ctx = self._ctx(tmp_path)
        ctx.config = self._full_config()
        # backend stays None
        with pytest.raises(icontract.ViolationError):
            _step_start_containers(ctx)

    def test_start_containers_routes_through_aces_handoff(self, mocker, tmp_path):
        from aptl.core.lab import LabResult, _step_start_containers

        ctx = self._ctx(tmp_path)
        ctx.config = self._full_config()
        ctx.backend = MagicMock()
        start_aces = mocker.patch(
            "aptl.core.lab.start_aces_scenario",
            return_value=LabResult(success=True, message="ok"),
        )

        result = _step_start_containers(ctx)

        assert result is None
        start_aces.assert_called_once_with(tmp_path, ctx.config, ctx.backend)

    # -- ssh_key_is_ready --------------------------------------------

    def test_test_ssh_without_ssh_key_raises_violation(self, tmp_path):
        import icontract

        from aptl.core.lab import _step_test_ssh

        ctx = self._ctx(tmp_path)
        ctx.config = self._full_config()
        # ssh_key_path stays None
        with pytest.raises(icontract.ViolationError):
            _step_test_ssh(ctx)

    # -- backend_is_initialized on additional consumers (codex finding #2)

    def test_sync_credentials_without_backend_raises_violation(self, tmp_path):
        """Reading `ctx.backend` for the SSHComposeBackend check falls
        through as local when backend is None, which would render
        credentials to the wrong host. Issue #214 / codex cycle 1."""
        import icontract

        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(tmp_path)
        ctx.env = self._full_env()
        # backend stays None
        with pytest.raises(icontract.ViolationError):
            _step_sync_credentials(ctx)

    def test_sync_suricata_baselines_without_backend_raises_violation(self, tmp_path):
        """Same SSHComposeBackend fall-through as `_step_sync_credentials`."""
        import icontract

        from aptl.core.lab import _step_sync_suricata_misp_rule_baselines

        ctx = self._ctx(tmp_path)
        # backend stays None
        with pytest.raises(icontract.ViolationError):
            _step_sync_suricata_misp_rule_baselines(ctx)

    def test_capture_snapshot_without_backend_raises_violation(self, tmp_path):
        """`capture_snapshot(backend=None)` is meaningless; refuse rather
        than let the snapshot step blow up later."""
        import icontract

        from aptl.core.lab import _step_capture_snapshot

        ctx = self._ctx(tmp_path)
        # backend stays None
        with pytest.raises(icontract.ViolationError):
            _step_capture_snapshot(ctx)

    # -- contracts survive `python -O` (codex finding #1) --------------

    def test_contracts_are_unconditionally_enabled(self):
        """`icontract.require` defaults `enabled` to `__debug__`; under
        `python -O` the decorator is silently disabled and the
        precondition vanishes — defeating the whole `assert` →
        `icontract` migration. Issue #214 / codex cycle 1 flagged this
        as a `class` defect; the `_runtime_require` wrapper must pin
        `enabled=True` so every production guard fires regardless of
        the interpreter flag.

        We assert this property two ways: (1) introspect the wrapper's
        product so a future refactor that flips `enabled` to False is
        caught at the boundary; (2) structurally exercise the wrapper
        on a throwaway always-false predicate and confirm it really
        does raise `ViolationError`, so a future refactor that keeps
        the `enabled=True` literal but otherwise short-circuits the
        decorator (e.g. swapping in a different decorator class) is
        also caught."""
        import icontract

        from aptl.core.lab import _runtime_require

        # (1) Introspection: the assembled decorator must report enabled.
        decorator = _runtime_require(lambda x: True, description="probe")
        assert decorator.enabled is True

        # (2) Structural: an always-false predicate must actually raise.
        @_runtime_require(lambda value: False, description="always_false")
        def _probe(value):
            return value

        with pytest.raises(icontract.ViolationError):
            _probe("anything")

    # -- start_lab requires a populated config -----------------------

    def test_start_lab_with_none_config_raises_violation(self):
        import icontract

        from aptl.core.lab import start_lab

        with pytest.raises(icontract.ViolationError):
            start_lab(None)  # type: ignore[arg-type]

    # -- contract descriptions must not embed secret-bearing repr ----

    def test_violation_message_does_not_expose_envvars_repr(self, tmp_path):
        """Contract failure for env_is_loaded must not surface a `repr(EnvVars)`
        substring. ADR-031: descriptions are narrow labels."""
        import icontract

        from aptl.core.lab import _step_sync_credentials

        ctx = self._ctx(tmp_path)  # env stays None
        try:
            _step_sync_credentials(ctx)
            assert False, "expected ViolationError"
        except icontract.ViolationError as exc:
            text = str(exc)
            # The label must be a narrow, attributable string the CLI can
            # grep for; raw `EnvVars(...)` repr must not appear.
            assert "EnvVars(" not in text
            assert "api_password" not in text
            assert "INDEXER_PASSWORD" not in text

    def test_violation_with_secret_bearing_ctx_stays_narrow(self, tmp_path):
        """Tougher property (codex cycle 2 finding #1): when a contract
        fires AFTER `_step_load_env` has populated `ctx.env` with real
        secrets, the violation message must STILL be a narrow label —
        not just the env-is-None case. icontract's default renderer
        would otherwise interpolate `ctx`'s repr (including
        `wazuh_cluster_key`, which the existing string redactor does
        not mask). `_runtime_require`'s `error=` callback pins the
        message to the description string."""
        import icontract

        from aptl.core.env import EnvVars
        from aptl.core.lab import _LabStartContext, _step_test_ssh

        # Populate env with secret-shaped values; leave ssh_key_path
        # None so the `ssh_key_is_ready` contract fires.
        ctx = _LabStartContext(
            project_dir=tmp_path,
            skip_seed=False,
            env=EnvVars(
                indexer_username="admin",
                indexer_password="indexer-secret-do-not-leak",
                api_username="wazuh-wui",
                api_password="api-secret-do-not-leak",
                wazuh_cluster_key="cluster-key-do-not-leak",
            ),
            config=self._full_config(),
            backend=MagicMock(),
            # ssh_key_path stays None — triggers the contract.
        )

        try:
            _step_test_ssh(ctx)
            assert False, "expected ViolationError"
        except icontract.ViolationError as exc:
            text = str(exc)
            # Narrow description survives.
            assert "ssh_key_is_ready" in text
            # None of the secret-shaped env values leak.
            assert "indexer-secret-do-not-leak" not in text
            assert "api-secret-do-not-leak" not in text
            assert "cluster-key-do-not-leak" not in text
            # Nor does any context repr framing.
            assert "_LabStartContext(" not in text
            assert "EnvVars(" not in text
            assert "ctx was" not in text


class TestOrchestrateLabStartContractMapping:
    """The orchestrator translates an `icontract.ViolationError` raised
    inside a step into a fatal `LabResult` with a redacted narrow message
    (ADR-031 § Decision). Operators must never see raw violation text
    from a secret-bearing object's `repr()`.
    """

    def test_contract_violation_inside_step_yields_failed_labresult(
        self, mocker, tmp_path
    ):
        import icontract

        from aptl.core.lab import orchestrate_lab_start
        from aptl.core.lab_types import StartupOutcome

        # `_LAB_START_STEPS` is a tuple of function references captured at
        # import time, so patching the module-attribute `_step_load_env`
        # would not change what the orchestrator runs. Substitute the
        # tuple itself with a single fake step that raises the violation.
        def fake_step(ctx):
            raise icontract.ViolationError(
                "env_is_loaded(ctx.env): the contract is violated. "
                "ctx was _LabStartContext(env=EnvVars(api_password='hunter2'))"
            )

        fake_step.__name__ = "_step_load_env"
        mocker.patch("aptl.core.lab._LAB_START_STEPS", (fake_step,))

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert result.outcome is StartupOutcome.FAILED
        # Narrow template; carries the step name for attribution but
        # never the raw violation text or any context repr().
        assert "_step_load_env" in (result.error or "")
        assert "contract" in (result.error or "").lower()
        # Raw violation prose / secret-shaped substrings must not leak.
        assert "ctx.env" not in (result.error or "")
        assert "EnvVars(" not in (result.error or "")
        assert "hunter2" not in (result.error or "")


class TestStopLabCleanupIsContractFree:
    """ADR-031 non-goal: `stop_lab` and other cleanup paths must keep
    working when config/env is missing. They are intentionally not
    decorated with `icontract.require`.
    """

    def test_stop_lab_with_missing_config_succeeds(self, mocker, tmp_path):
        from aptl.core.lab import LabResult, stop_lab

        backend = MagicMock()
        backend.stop.return_value = LabResult(
            success=True, message="stopped"
        )

        result = stop_lab(project_dir=tmp_path, backend=backend)

        assert result.success is True
        # Fell back to ALL_KNOWN_PROFILES since no aptl.json exists.
        backend.stop.assert_called_once()
        called_profiles = backend.stop.call_args[0][0]
        assert "wazuh" in called_profiles


class TestSeedSocPrimeProfileDiagnostic:
    """Soft check against the reusable `required_profiles_enabled`
    predicate at the SOC seed boundary. ADR-005 supports selective SOC
    labs, so a missing prime profile must NOT fatally refuse lab
    startup — it surfaces as a CAPABILITY diagnostic and the step
    returns None. The reusable predicate remains available as a hard
    contract for a future explicit prime-scenario entrypoint."""

    def _ctx(self, tmp_path: Path, *, soc: bool, **extra):
        from aptl.core.config import AptlConfig
        from aptl.core.env import EnvVars
        from aptl.core.lab import _LabStartContext

        containers = {"wazuh": True, "victim": True, "kali": True, "soc": soc}
        containers.update(extra)
        return _LabStartContext(
            project_dir=tmp_path,
            skip_seed=False,
            env=EnvVars(
                indexer_username="u",
                indexer_password="p",
                api_username="u",
                api_password="p",
            ),
            config=AptlConfig(
                lab={"name": "t"}, containers=containers
            ),
        )

    def test_partial_prime_set_emits_capability_diagnostic(self, tmp_path):
        """SOC enabled but enterprise/fileshare missing → CAPABILITY
        warning naming the missing profiles, step returns None.
        Selective SOC labs (ADR-005) must remain valid."""
        from aptl.core.lab import _step_seed_soc
        from aptl.core.lab_types import DiagnosticImpact, DiagnosticSeverity

        ctx = self._ctx(tmp_path, soc=True, enterprise=False, fileshare=False)
        result = _step_seed_soc(ctx)

        assert result is None  # non-fatal
        assert len(ctx.diagnostics) == 1
        diag = ctx.diagnostics[0]
        assert diag.step == "seed_soc"
        assert diag.impact is DiagnosticImpact.CAPABILITY
        assert diag.severity is DiagnosticSeverity.WARNING
        assert "enterprise" in diag.message
        assert "fileshare" in diag.message
        # Operator action must guide them to enable the profiles.
        assert "aptl.json" in diag.operator_action

    def test_full_prime_set_runs_no_prime_diagnostic(self, tmp_path):
        """SOC enabled and every prime profile enabled → predicate is
        satisfied, no prime-related diagnostic. (A separate diagnostic
        for the missing seed script may still fire — that is the
        existing seed-script-missing path, not the prime check.)"""
        from aptl.core.lab import _step_seed_soc

        ctx = self._ctx(
            tmp_path,
            soc=True,
            enterprise=True,
            fileshare=True,
        )
        result = _step_seed_soc(ctx)
        assert result is None
        # The only diagnostic possible here is the missing-seed-script
        # one (tmp_path has no scripts/seed-prime.sh); the prime-profile
        # diagnostic must not have fired.
        prime_diags = [
            d for d in ctx.diagnostics
            if "prime profile" in d.message.lower()
        ]
        assert prime_diags == []

    def test_soc_disabled_skips_predicate(self, tmp_path):
        """When SOC is disabled the seed step is a no-op; the prime-
        profile predicate must not fire (ADR-031: profile checks are
        operation-scoped, not global)."""
        from aptl.core.lab import _step_seed_soc

        ctx = self._ctx(tmp_path, soc=False, enterprise=False, fileshare=False)
        result = _step_seed_soc(ctx)
        assert result is None
        assert ctx.diagnostics == []


class TestGenerateSocCertsStep:
    """SEC-006 / ADR-034: lab-start materializes the SOC CA + per-tool
    server certs before `_step_check_bind_mounts` runs, so every
    Compose bind mount that references `config/soc_certs/...` resolves
    cleanly on first boot.
    """

    def _ctx(self, tmp_path: Path, *, soc: bool, backend=None):
        from aptl.core.config import AptlConfig
        from aptl.core.env import EnvVars
        from aptl.core.lab import _LabStartContext

        containers = {"wazuh": True, "victim": True, "kali": True, "soc": soc}
        return _LabStartContext(
            project_dir=tmp_path,
            skip_seed=False,
            env=EnvVars(
                indexer_username="u",
                indexer_password="p",
                api_username="u",
                api_password="p",
            ),
            config=AptlConfig(lab={"name": "t"}, containers=containers),
            backend=backend or MagicMock(),
        )

    def test_skips_when_soc_disabled(self, tmp_path, mocker):
        """SOC disabled → no CA generation, no diagnostics."""
        from aptl.core.lab import _step_generate_soc_certs

        spy = mocker.patch("aptl.core.lab.ensure_soc_certs")
        ctx = self._ctx(tmp_path, soc=False)
        result = _step_generate_soc_certs(ctx)
        assert result is None
        assert ctx.diagnostics == []
        spy.assert_not_called()

    def test_calls_ensure_soc_certs_with_project_dir_when_soc_enabled(
        self, tmp_path, mocker
    ):
        from aptl.core.lab import _step_generate_soc_certs
        from aptl.core.soc_ca import CertResult

        spy = mocker.patch(
            "aptl.core.lab.ensure_soc_certs",
            return_value=CertResult(success=True, generated=True, certs_dir=tmp_path),
        )
        ctx = self._ctx(tmp_path, soc=True)
        result = _step_generate_soc_certs(ctx)
        assert result is None
        spy.assert_called_once_with(tmp_path)

    def test_returns_failed_labresult_on_cert_generation_failure(
        self, tmp_path, mocker
    ):
        from aptl.core.lab import _step_generate_soc_certs
        from aptl.core.soc_ca import CertResult

        mocker.patch(
            "aptl.core.lab.ensure_soc_certs",
            return_value=CertResult(
                success=False,
                generated=False,
                error="something went wrong",
            ),
        )
        ctx = self._ctx(tmp_path, soc=True)
        result = _step_generate_soc_certs(ctx)
        assert result is not None
        assert result.success is False
        assert "soc" in (result.error or "").lower()

    def test_ssh_remote_backend_refuses_with_adr_028_message(self, tmp_path, mocker):
        """ADR-028: generated artifacts materialize on the host running
        `aptl lab start`. With an SSH-remote backend the daemon is on
        another host, so the bind mounts would not see them — refuse
        with the same shape as `_step_sync_credentials`."""
        from aptl.core.deployment import SSHComposeBackend
        from aptl.core.lab import _step_generate_soc_certs

        # Cert generator must NOT run when we refuse early.
        spy = mocker.patch("aptl.core.lab.ensure_soc_certs")

        backend = MagicMock(spec=SSHComposeBackend)
        ctx = self._ctx(tmp_path, soc=True, backend=backend)
        result = _step_generate_soc_certs(ctx)

        assert result is not None
        assert result.success is False
        assert "remote" in (result.error or "").lower()
        spy.assert_not_called()

    def test_runs_before_check_bind_mounts_in_step_sequence(self):
        """ADR-028 sequencing: generated cert files must exist before
        `_check_bind_mounts` inspects the Compose mount list. Encode
        the ordering as a test so a future refactor cannot quietly
        invert the two and let the lab boot fail with a missing
        bind-mount source."""
        from aptl.core.lab import (
            _LAB_START_STEPS,
            _step_check_bind_mounts,
            _step_generate_soc_certs,
        )

        names = [s.__name__ for s in _LAB_START_STEPS]
        assert "_step_generate_soc_certs" in names
        i_soc = names.index("_step_generate_soc_certs")
        i_mounts = names.index("_step_check_bind_mounts")
        assert i_soc < i_mounts, (
            f"_step_generate_soc_certs must precede _step_check_bind_mounts; "
            f"got order {names[i_soc]} → ... → {names[i_mounts]}"
        )
