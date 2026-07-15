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
