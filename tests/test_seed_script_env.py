"""Credential discovery for participant-invoked SOC seed scripts."""

from __future__ import annotations

import os
import json
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
HELPER = PROJECT_ROOT / "scripts" / "aptl-env.sh"


def _load_key(env_file: Path, key: str, *, existing: str = "") -> str:
    env = {
        **os.environ,
        "APTL_ENV_HELPER": str(HELPER),
        "APTL_TEST_ENV_FILE": str(env_file),
        "APTL_TEST_KEY": key,
    }
    if existing:
        env[key] = existing
    else:
        env.pop(key, None)
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$APTL_ENV_HELPER"; '
            'aptl_load_env_key "$APTL_TEST_ENV_FILE" "$APTL_TEST_KEY"; '
            'printf "%s" "${!APTL_TEST_KEY}"',
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_loads_generated_key_from_project_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("MISP_API_KEY=fresh-lab-key\n")

    assert _load_key(env_file, "MISP_API_KEY") == "fresh-lab-key"


def test_explicit_process_environment_wins(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("MISP_API_KEY=file-key\n")

    assert _load_key(env_file, "MISP_API_KEY", existing="operator-key") == (
        "operator-key"
    )


def test_env_value_is_not_evaluated(tmp_path):
    marker = tmp_path / "must-not-exist"
    literal = f"$(touch {marker})"
    env_file = tmp_path / ".env"
    env_file.write_text(f"MISP_API_KEY={literal}\n")

    assert _load_key(env_file, "MISP_API_KEY") == literal
    assert not marker.exists()


def test_manual_seed_entrypoints_load_their_required_credentials():
    expected = {
        "seed-prime.sh": ("MISP_API_KEY", "SHUFFLE_API_KEY"),
        "seed-misp.sh": ("MISP_API_KEY",),
        "seed-shuffle.sh": (
            "MISP_API_KEY",
            "SHUFFLE_API_KEY",
            "THEHIVE_API_KEY",
        ),
    }
    for name, keys in expected.items():
        text = (PROJECT_ROOT / "scripts" / name).read_text()
        assert 'source "$SCRIPT_DIR/aptl-env.sh"' in text
        for key in keys:
            assert key in text


def test_seeded_soar_case_preserves_exact_alert_id_and_mcp_uses_flat_argument():
    seed = (PROJECT_ROOT / "scripts" / "seed-shuffle.sh").read_text()
    assert r"Wazuh alert id \$exec.id; rule \$exec.rule.id" in seed

    config = json.loads(
        (PROJECT_ROOT / "mcp" / "mcp-soar" / "docker-lab-config.json").read_text()
    )
    description = config["queries"]["execute_workflow"]["description"]
    assert "body itself becomes the execution argument" in description
    assert '"execution_argument"' not in description


def test_thehive_seed_uses_declared_https_endpoint_and_mounted_ca():
    script = (PROJECT_ROOT / "scripts" / "thehive-apikey.sh").read_text()
    assert 'THEHIVE_URL="${THEHIVE_URL:-https://localhost:9000}"' in script
    assert (
        'THEHIVE_CA_CERT="${THEHIVE_CA_CERT:-/opt/techvault/soc-certs/lab-ca.pem}"'
        in script
    )
    assert 'curl --cacert "$THEHIVE_CA_CERT"' in script


@pytest.mark.parametrize("script_name", ["thehive-apikey.sh", "cortex-apikey.sh"])
def test_seed_credentials_never_enter_docker_exec_argv(tmp_path, script_name):
    fake = tmp_path / "bin"
    fake.mkdir()
    log = tmp_path / "argv.jsonl"
    docker = fake / "docker"
    docker.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["ARGV_LOG"], "a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\\n")
if "mktemp" in sys.argv:
    print("/tmp/test-cookie")
    raise SystemExit(0)
if "/api/status" in " ".join(sys.argv) + sys.stdin.read():
    print("{}")
    raise SystemExit(0)
raise SystemExit(1)
''')
    docker.chmod(0o755)
    secret = "regression-secret-do-not-publish"
    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / "scripts" / script_name)],
        env={**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "ARGV_LOG": str(log),
             "THEHIVE_ADMIN_PASS": secret, "CORTEX_ADMIN_KEY": secret,
             "CORTEX_API_KEY": secret + "-connector"},
        capture_output=True, text=True, timeout=30,
    )
    assert log.exists()
    assert secret not in log.read_text()
    assert secret not in result.stdout + result.stderr
