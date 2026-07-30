"""Published ``raes`` CLI invocations used by the TechVault static gate.

Split out of ``_gate_checks.py`` to keep that module within the S104
file-length budget; behaviour is unchanged. These helpers shell out to the
installed ``raes`` CLI (conformance and import verification) and normalise its
output into gate diagnostics, returning ``None`` when the CLI is unavailable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

from aptl.utils.redaction import redact

_SUBPROCESS_TIMEOUT_S = 120


def conformance_cli_diagnostics(
    profile: str, fixtures_root: Path | None, profiles_root: Path | None
) -> list[str]:
    """Run the published ``raes conformance backend`` command and report failures."""
    cli = ["conformance", "backend", "--profile", profile]
    if fixtures_root is not None:
        cli += ["--fixtures-root", str(fixtures_root)]
    if profiles_root is not None:
        cli += ["--profiles-root", str(profiles_root)]
    result = run_raes(cli)
    if result is None:
        return ["`raes` CLI not found on PATH; conformance command is unavailable"]
    if result.returncode != 0:
        return [redact(f"raes conformance backend exited non-zero: {_cli_detail(result)}")]
    return []


def verify_imports_diagnostics(
    result: subprocess.CompletedProcess[str] | None,
) -> list[str]:
    """Turn an ``raes sdl verify-imports`` run into gate diagnostics."""
    if result is None:
        return ["`raes` CLI not found on PATH; RAES import tooling is unavailable"]
    if result.returncode != 0:
        return [redact(f"raes sdl verify-imports failed: {_cli_detail(result)}")]
    return []


def run_raes(
    args: Sequence[str], *, timeout: int = _SUBPROCESS_TIMEOUT_S
) -> subprocess.CompletedProcess[str] | None:
    """Run an ``raes`` subcommand, returning None when the CLI is unavailable."""
    executable = shutil.which("raes")
    if executable is None:
        return None
    # Fixed argv (resolved executable, subcommand, paths/profile), no shell;
    # S603 is a false positive for this trusted, non-interpolated invocation.
    return subprocess.run(
        [executable, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _cli_detail(result: subprocess.CompletedProcess[str]) -> str:
    """Extract a concise, structured failure detail from a conformance run."""
    payload = result.stdout.strip()
    if payload:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, Mapping):
            codes = sorted(
                {
                    d.get("code", "?")
                    for d in data.get("diagnostics", [])
                    if isinstance(d, Mapping)
                }
            )
            if codes:
                return f"exit={result.returncode} diagnostics={codes}"
    tail = (result.stderr or result.stdout or "").strip().splitlines()
    return f"exit={result.returncode} {tail[-1] if tail else ''}".strip()
