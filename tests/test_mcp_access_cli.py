"""Public CLI binds configuration to explicit authenticated instance inputs."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typer.testing import CliRunner

from aptl.cli.main import app
from tests.test_mcp_access import access_record, grant


def test_configure_emits_both_native_clients_without_provider_auth(tmp_path):
    from aptl.workbench.dispatch import key_fingerprint

    key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )
    fingerprint = key_fingerprint(key)
    record = access_record(host_key_fingerprint=fingerprint)
    record_path = tmp_path / "access.json"
    record_path.write_text(record.model_dump_json())
    grant_path = tmp_path / "grant.json"
    grant_path.write_text(grant().model_dump_json())
    key_path = tmp_path / "host.pub"
    key_path.write_text(key)
    for client in ("claude", "codex"):
        result = CliRunner().invoke(
            app,
            [
                "mcp-access",
                "configure",
                "--access-record",
                str(record_path),
                "--grant",
                str(grant_path),
                "--host-public-key",
                str(key_path),
                "--expected-host-key",
                fingerprint,
                "--identity-file",
                str(tmp_path / "transport-key"),
                "--username",
                "aptl-mcp",
                "--owner-id",
                "alice",
                "--seat-id",
                "seat-1",
                "--instance-id",
                "instance-1",
                "--project-dir",
                str(tmp_path),
                "--client",
                client,
            ],
        )
        assert result.exit_code == 0, result.output
    assert (tmp_path / ".mcp.json").exists()
    assert (tmp_path / ".codex/config.toml").exists()


def test_dispatch_does_not_accept_shell_selectors(tmp_path, monkeypatch):
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "bash -c id")
    result = CliRunner().invoke(
        app,
        [
            "mcp-access",
            "dispatch",
            "--binding",
            str(tmp_path / "absent"),
            "--grant-id",
            "grant-1",
            "--key-fingerprint",
            "SHA256:" + "B" * 43,
        ],
    )
    assert result.exit_code == 2
    assert "transport request rejected" in result.output
