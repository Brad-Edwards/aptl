"""A failed server install must fail the packaged build, not skip a server."""

import os
import shutil
import subprocess
from pathlib import Path


def test_build_stops_at_first_failed_server(tmp_path):
    root = Path(__file__).resolve().parents[1]
    script = tmp_path / "build-all-mcps.sh"
    shutil.copyfile(root / "mcp/build-all-mcps.sh", script)
    for name in ("aptl-mcp-common", "mcp-red", "mcp-reverse"):
        (tmp_path / name).mkdir()
    binary = tmp_path / "bin"
    binary.mkdir()
    npm = binary / "npm"
    npm.write_text('#!/bin/sh\ncase "$PWD" in */mcp-red) exit 23;; esac\n')
    npm.chmod(0o755)
    result = subprocess.run(
        ["bash", str(script)],
        env={**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 23
    assert "Building mcp-reverse" not in result.stdout
    assert "built successfully" not in result.stdout
