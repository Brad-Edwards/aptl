"""The SSH dispatcher is a protocol boundary, never a command runner."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aptl.workbench.dispatch import (
    DispatchSelector,
    ProtocolAdmission,
    restricted_key,
    sshd_policy,
)
from aptl.workbench.profiles import profile_for


def test_selector_accepts_only_fixed_version_instance_generation_and_server():
    assert DispatchSelector.parse("aptl-mcp-v1 instance-1 2 aptl-red").generation == 2
    for selector in (
        "bash",
        "aptl-mcp-v1 instance-1 2 aptl-red; id",
        "aptl-mcp-v1 ../other 2 aptl-red",
        "aptl-mcp-v1 instance-1 02 aptl-red",
        "aptl-mcp-v1 instance-1 2 aptl-red extra",
    ):
        with pytest.raises(ValueError):
            DispatchSelector.parse(selector)


def test_protocol_denies_unlisted_tools_and_non_mcp_capabilities():
    gate = ProtocolAdmission(profile_for("red").servers[0])
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "client", "version": "1"},
        },
    }
    gate.request(initialize)
    gate.admit_inventory(
        {"tools": [{"name": name} for name in profile_for("red").servers[0].tool_names]}
    )
    gate.request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "kali_info", "arguments": {}},
        }
    )
    for message in (
        {"method": "tools/call", "params": {"name": "indexer_query", "arguments": {}}},
        {"method": "resources/read", "params": {"uri": "file:///etc/shadow"}},
        {"method": "tools/call", "params": {"name": "kali_info", "arguments": []}},
    ):
        with pytest.raises(ValueError):
            gate.request({"jsonrpc": "2.0", "id": 3, **message})


def test_protocol_fails_closed_on_inventory_drift_and_calls_before_init():
    gate = ProtocolAdmission(profile_for("red").servers[0])
    with pytest.raises(ValueError):
        gate.request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "kali_info", "arguments": {}},
            }
        )
    with pytest.raises(ValueError):
        gate.admit_inventory(
            {"tools": [{"name": "kali_info"}, {"name": "guest_shell"}]}
        )


def test_sshd_disables_other_channels_and_binds_key_to_forced_dispatcher(tmp_path):
    policy = sshd_policy(
        port=2222,
        username="aptl-mcp",
        host_key=tmp_path / "host_key",
        authorized_keys=tmp_path / "authorized_keys",
    )
    for control in (
        "DisableForwarding yes",
        "PermitTTY no",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitUserEnvironment no",
        "PermitUserRC no",
        "AuthenticationMethods publickey",
    ):
        assert control in policy
    public = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )
    key = restricted_key(
        public_key=public,
        executable=tmp_path / "aptl",
        binding=tmp_path / "binding.json",
        grant_id="grant-1",
    )
    assert key.startswith('restrict,command="')
    assert "mcp-access dispatch" in key
    assert "--grant-id grant-1" in key
    assert "SSH_ORIGINAL_COMMAND" not in key


def test_generated_policy_is_accepted_by_real_openssh(tmp_path):
    import shutil
    import subprocess

    sshd = shutil.which("sshd")
    keygen = shutil.which("ssh-keygen")
    if sshd is None or keygen is None:
        pytest.skip("OpenSSH server tooling is unavailable")
    key = tmp_path / "host_key"
    subprocess.run(
        [keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    config = tmp_path / "sshd_config"
    config.write_text(
        sshd_policy(
            port=2222,
            username="aptl-mcp",
            host_key=key,
            authorized_keys=tmp_path / "authorized_keys",
        )
    )
    result = subprocess.run(
        [sshd, "-T", "-f", str(config)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    settings = dict(line.split(" ", 1) for line in result.stdout.splitlines())
    for name in (
        "passwordauthentication",
        "kbdinteractiveauthentication",
        "permittty",
        "allowtcpforwarding",
        "allowagentforwarding",
        "permituserenvironment",
    ):
        assert settings[name] == "no"
    assert settings["authenticationmethods"] == "publickey"
    assert settings["disableforwarding"] == "yes"
