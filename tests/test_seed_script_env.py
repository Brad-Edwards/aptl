"""Credential discovery for participant-invoked SOC seed scripts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


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


def test_thehive_provisioner_reuses_a_working_key(tmp_path):
    """A seed rerun must not revoke the key held by the Shuffle workflow."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        """#!/usr/bin/env python3
import sys

args = sys.argv[1:]
if (
    "https://thehive.invalid/api/v1/query" in args
    and "Authorization: Bearer ExistingKey123" in args
):
    raise SystemExit(0)
raise SystemExit(88)
""",
        encoding="utf-8",
    )
    fake_curl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "THEHIVE_API_KEY": "ExistingKey123",
        "THEHIVE_URL": "https://thehive.invalid",
        "THEHIVE_CACERT": str(tmp_path / "missing-ca.pem"),
    }

    result = subprocess.run(
        [PROJECT_ROOT / "scripts" / "thehive-apikey.sh"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ExistingKey123"


def test_existing_shuffle_workflow_refreshes_seeded_credentials():
    """An idempotent rerun must repair credentials and webhook metadata."""
    text = (PROJECT_ROOT / "scripts" / "seed-shuffle.sh").read_text()

    assert "refresh_workflow_credentials()" in text
    assert 'refresh_workflow_credentials "$EXISTING_ID"' in text
    assert 'os.environ["MISP_API_KEY"]' in text
    assert 'os.environ["THEHIVE_API_KEY"]' in text
    assert "> /tmp/aptl_shuffle_webhook_url" in text


def test_shuffle_http_actions_use_supported_tls_and_safe_enrichment():
    """The bundled HTTP app names its TLS argument ``verify``."""
    text = (PROJECT_ROOT / "scripts" / "seed-shuffle.sh").read_text()

    assert '"name": "verify_ssl"' not in text
    assert text.count('{"name": "verify", "value": "false"}') == 2
    assert "$misp_ip_lookup.body.response.Attribute.#0.value" in text
