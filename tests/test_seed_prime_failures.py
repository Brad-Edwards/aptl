"""Failure reporting for the full TechVault prime seed."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def test_required_seed_failure_returns_nonzero_and_names_component(tmp_path):
    project = tmp_path / "project"
    scripts = project / "scripts"
    fake_bin = tmp_path / "bin"
    scripts.mkdir(parents=True)
    fake_bin.mkdir()
    shutil.copy2(PROJECT_ROOT / "scripts" / "seed-prime.sh", scripts)
    (scripts / "seed-prime.sh").chmod(0o755)
    env_helper = PROJECT_ROOT / "scripts" / "aptl-env.sh"
    if env_helper.exists():
        shutil.copy2(env_helper, scripts)

    _write_executable(scripts / "thehive-apikey.sh", "#!/bin/sh\nexit 1\n")
    _write_executable(
        scripts / "cortex-apikey.sh",
        "#!/bin/sh\nprintf 'cortex-test-key\\n'\n",
    )
    _write_executable(scripts / "seed-misp.sh", "#!/bin/sh\nexit 0\n")
    _write_executable(
        scripts / "seed-shuffle.sh",
        "#!/bin/sh\nprintf 'http://shuffle.invalid/hook' > "
        '"$APTL_SHUFFLE_WEBHOOK_FILE"\n',
    )
    _write_executable(
        fake_bin / "docker",
        """#!/bin/sh
if [ "$1" = inspect ]; then
    printf 'healthy\n'
elif [ "$1 $2 $3" = "exec aptl-workstation cat" ]; then
    printf 'ssh-rsa AAAATEST participant@workstation\n'
elif [ "$1 $2 $3" = "exec aptl-victim grep" ]; then
    printf '1\n'
fi
""",
    )
    _write_executable(
        fake_bin / "curl",
        "#!/bin/sh\nprintf '{\"status\":\"green\"}\\n'\n",
    )
    webhook_file = tmp_path / "shuffle-webhook"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "APTL_SHUFFLE_WEBHOOK_FILE": str(webhook_file),
    }

    result = subprocess.run(
        [scripts / "seed-prime.sh"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 1
    assert "Prime Scenario Seed Incomplete" in result.stdout
    assert "- TheHive API key" in result.stdout
    assert "Prime Scenario Seed Complete" not in result.stdout
