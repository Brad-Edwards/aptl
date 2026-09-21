"""Tests for the issue #825 hosted-seat operator helper."""

from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path

import pytest


HELPER_PATH = (
    Path(__file__).resolve().parents[1] / "tools" / "workshop" / "hosted_seat.py"
)


def _load_helper():
    spec = importlib.util.spec_from_file_location("hosted_seat", HELPER_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def helper():
    return _load_helper()


@pytest.mark.parametrize(
    "seat_id",
    [*(f"seat{index:02d}" for index in range(1, 13))],
)
def test_only_canonical_class_seats_are_accepted(helper, seat_id: str) -> None:
    assert helper.validate_seat_id(seat_id) == seat_id


@pytest.mark.parametrize(
    "seat_id",
    [
        "seat00",
        "seat13",
        "seat1",
        "SEAT01",
        "../seat01",
        "seat01.example.com",
        "participant01",
        "",
    ],
)
def test_noncanonical_seats_are_rejected(helper, seat_id: str) -> None:
    with pytest.raises(ValueError, match="seat01 through seat12"):
        helper.validate_seat_id(seat_id)


@pytest.mark.parametrize(
    "hostname",
    [
        "*.labs.example.com",
        "seat01",
        "seat01..example.com",
        "Seat01.labs.example.com",
        "seat01.labs.example.com.",
        "seat01_labs.example.com",
        "-seat01.labs.example.com",
        "127.0.0.1",
        "seat01.labs.example.com:443",
    ],
)
def test_unsafe_or_noncanonical_hostnames_are_rejected(helper, hostname: str) -> None:
    with pytest.raises(ValueError, match="canonical lowercase DNS hostname"):
        helper.validate_hostname(hostname)


def test_hostname_must_match_the_seat(helper) -> None:
    with pytest.raises(ValueError, match="must start with seat01"):
        helper.validate_seat_hostname("seat01", "seat02.labs.example.com")


def test_rendered_dcv_config_is_loopback_system_auth_and_exact_host(helper) -> None:
    rendered = helper.render_dcv_config("seat01.labs.example.com")

    assert 'authentication="system"' in rendered
    assert 'pam-service-name="dcv"' in rendered
    assert "web-listen-endpoints=['127.0.0.1:8443', '[::1]:8443']" in rendered
    assert "enable-quic-frontend=false" in rendered
    assert (
        'allowed-http-host-regex="^seat01\\.labs\\.example\\.com(:443)?$"' in rendered
    )
    assert (
        'allowed-ws-origin-regex="^https://seat01\\.labs\\.example\\.com'
        '(:443)?$"' in rendered
    )
    assert "0.0.0.0" not in rendered
    assert 'authentication="none"' not in rendered


def test_rendered_caddyfile_has_exact_host_and_verified_loopback_tls(helper) -> None:
    rendered = helper.render_caddyfile("seat01.labs.example.com")

    assert "seat01.labs.example.com {" in rendered
    assert "reverse_proxy https://127.0.0.1:8443" in rendered
    assert "header_up Host seat01.labs.example.com" in rendered
    assert "tls_server_name seat01.labs.example.com" in rendered
    assert "tls_trust_pool file /etc/dcv/dcv-upstream-ca.pem" in rendered
    assert "protocols h1 h2" in rendered
    assert "h3" not in rendered
    assert "tls_insecure_skip_verify" not in rendered
    assert "\n:8443 {" not in rendered
    assert "*." not in rendered


def test_host_port_overrides_reserve_caddy_and_dcv_ports(helper) -> None:
    assert helper.host_port_overrides() == {
        "APTL_HP_WAZUH_DASHBOARD_5601": "9443",
        "APTL_HP_MISP_443": "9444",
    }


def test_dcv_permissions_limit_the_owner_to_interactive_desktop_features(
    helper,
) -> None:
    assert helper.render_dcv_permissions() == (
        "[permissions]\n%owner% allow display keyboard mouse pointer audio-out\n"
    )


def test_prepare_creates_private_create_once_state_without_disclosing_secret(
    helper, tmp_path: Path, capsys
) -> None:
    state_dir = tmp_path / "operator-state"

    result = helper.prepare_seat(
        state_dir=state_dir,
        trial_id="bh-arsenal-825-proof",
        seat_id="seat01",
        hostname="seat01.labs.example.com",
        token_bytes=lambda count: b"\x01" * count,
    )

    credentials = json.loads(result.credential_file.read_text(encoding="utf-8"))
    ledger = json.loads(result.ledger_file.read_text(encoding="utf-8"))
    assert credentials["username"] == "seat01"
    assert len(credentials["passphrase"]) >= 32
    assert credentials["passphrase"] not in result.public_summary()
    assert credentials["passphrase"] not in result.dcv_config_file.read_text()
    assert credentials["passphrase"] not in result.caddyfile.read_text()
    assert credentials["passphrase"] not in result.ledger_file.read_text()
    assert ledger == {
        "schema": "aptl.hosted-seat-input/v1",
        "trial_id": "bh-arsenal-825-proof",
        "seat_id": "seat01",
        "username": "seat01",
        "hostname": "seat01.labs.example.com",
        "dcv_upstream": "https://127.0.0.1:8443",
        "aws_profile": "catalyst-dev",
        "aws_region": "us-east-2",
    }
    assert capsys.readouterr().out == ""

    for directory in (
        state_dir,
        state_dir / "credentials",
        state_dir / "ledgers",
        state_dir / "generated",
        state_dir / "generated" / "seat01",
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for path in (
        result.credential_file,
        result.ledger_file,
        result.dcv_config_file,
        result.caddyfile,
        result.dcv_permissions_file,
        result.host_ports_file,
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    with pytest.raises(FileExistsError):
        helper.prepare_seat(
            state_dir=state_dir,
            trial_id="bh-arsenal-825-proof",
            seat_id="seat01",
            hostname="seat01.labs.example.com",
        )


def test_prepare_refuses_symlinked_state_directory(helper, tmp_path: Path) -> None:
    real_state = tmp_path / "real"
    real_state.mkdir()
    state_link = tmp_path / "operator-state"
    state_link.symlink_to(real_state, target_is_directory=True)

    with pytest.raises(ValueError, match="must not be a symlink"):
        helper.prepare_seat(
            state_dir=state_link,
            trial_id="bh-arsenal-825-proof",
            seat_id="seat01",
            hostname="seat01.labs.example.com",
        )


def test_cli_prints_only_a_nonsecret_machine_summary(
    helper, tmp_path: Path, capsys
) -> None:
    exit_code = helper.main(
        [
            "prepare",
            "--state-dir",
            str(tmp_path / "state"),
            "--trial-id",
            "bh-arsenal-825-proof",
            "--seat-id",
            "seat01",
            "--hostname",
            "seat01.labs.example.com",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    summary = json.loads(output)
    credential = json.loads(Path(summary["credential_file"]).read_text())
    assert credential["passphrase"] not in output
    assert summary["seat_id"] == "seat01"
    assert summary["hostname"] == "seat01.labs.example.com"


def test_mcp_registration_specs_select_only_the_profile_surface(
    helper, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aptl-red": {
                        "command": "node",
                        "args": ["/project/mcp-red/dist/index.js"],
                        "env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"},
                    },
                    "aptl-wazuh": {
                        "command": "node",
                        "args": ["/project/mcp-wazuh/dist/index.js"],
                    },
                    "facilitator-only": {
                        "command": "node",
                        "args": ["/project/facilitator.js"],
                        "env": {"SENSITIVE_VALUE": "must-not-be-admitted"},
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    specs = helper.load_mcp_registration_specs(project, ("aptl-red", "aptl-wazuh"))

    assert set(specs) == {"aptl-red", "aptl-wazuh"}
    assert specs["aptl-red"].argv == (
        "node",
        "/project/mcp-red/dist/index.js",
    )
    assert "SENSITIVE_VALUE" not in specs["aptl-red"].env
    assert specs["aptl-wazuh"].env == {}


def test_mcp_registration_specs_fail_closed_on_missing_or_invalid_entries(
    helper, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aptl-red": {
                        "command": "node",
                        "args": "not-a-list",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid MCP registration"):
        helper.load_mcp_registration_specs(project, ("aptl-red",))
    with pytest.raises(ValueError, match="missing MCP registration"):
        helper.load_mcp_registration_specs(project, ("aptl-wazuh",))
