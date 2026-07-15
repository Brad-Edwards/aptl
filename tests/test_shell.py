"""Tests for cross-platform POSIX shell-script execution.

Runs a real script through the resolver so Git Bash invocation is validated on
Windows and direct shebang execution on Unix.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from aptl.utils import shell


def _write_script(tmp_path: Path) -> Path:
    script = tmp_path / "hello.sh"
    script.write_text(
        '#!/bin/bash\necho "hello $1"\ncd "$(dirname "$0")" && pwd\n',
        encoding="utf-8",
        newline="\n",
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def test_runs_script_and_captures_output(tmp_path):
    script = _write_script(tmp_path)
    result = shell.run_shell_script(script, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "hello" in result.stdout


def test_passes_environment(tmp_path):
    script = tmp_path / "env.sh"
    script.write_text(
        '#!/bin/bash\necho "val=$APTL_TEST_VAR"\n',
        encoding="utf-8",
        newline="\n",
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    import os

    result = shell.run_shell_script(
        script, cwd=tmp_path, env={**os.environ, "APTL_TEST_VAR": "xyz"}
    )
    assert "val=xyz" in result.stdout


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only branch")
def test_find_posix_shell_none_on_unix():
    assert shell.find_posix_shell() is None


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows-only branch")
def test_find_git_bash_on_windows_not_wsl():
    found = shell.find_posix_shell()
    assert found is not None, "Git Bash should be discoverable on the Windows CI/dev host"
    assert not shell._looks_like_wsl(found), f"must not select the WSL shim: {found}"
    assert found.name.lower() == "bash.exe"


def test_looks_like_wsl_flags_system32():
    assert shell._looks_like_wsl(Path(r"C:\Windows\System32\bash.exe")) is True
    assert shell._looks_like_wsl(Path(r"C:\Program Files\Git\bin\bash.exe")) is False
