"""Cross-platform execution of the lab's POSIX shell scripts.

A couple of control-plane steps (MCP build, SOC seed) are bash scripts. On
Linux and macOS they run directly via their shebang. Windows has no POSIX shell
on PATH by default, so this locates **Git Bash** — the shell shipped with Git
for Windows, a native Windows program (MSYS2) — and runs the script through it.

WSL's ``C:\\Windows\\System32\\bash.exe`` is deliberately *not* used: it runs the
script inside a separate Linux distribution with its own filesystem and
toolchain (and often no Docker CLI), which is not the intended runtime. We only
accept a Git-for-Windows bash.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path, PureWindowsPath

from aptl.utils.logging import get_logger

log = get_logger("shell")

_IS_WINDOWS = sys.platform.startswith("win")


def _looks_like_wsl(path: Path) -> bool:
    """True for the WSL launcher shim under System32 (not a real POSIX shell)."""
    parts = {p.lower() for p in PureWindowsPath(path).parts}
    return "system32" in parts or "windowsapps" in parts


def _git_bash_from_git() -> Path | None:
    """Derive Git Bash from the ``git`` executable on PATH.

    Git for Windows lays out ``<root>\\cmd\\git.exe`` alongside
    ``<root>\\bin\\bash.exe``; that bash is the native MSYS2 shell.
    """
    git = shutil.which("git")
    if not git:
        return None
    root = Path(git).resolve().parent.parent  # <root>/cmd/git.exe -> <root>
    candidate = root / "bin" / "bash.exe"
    return candidate if candidate.is_file() else None


def _git_bash_from_known_locations() -> Path | None:
    for base in (
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("LocalAppData", ""),
    ):
        if not base:
            continue
        candidate = Path(base) / "Git" / "bin" / "bash.exe"
        if candidate.is_file():
            return candidate
    return None


def find_posix_shell() -> Path | None:
    """Return a POSIX shell for running ``.sh`` scripts, or None to run direct.

    Non-Windows returns None (the script runs via its shebang). On Windows this
    returns a Git-for-Windows ``bash.exe``, never the WSL launcher. Returns None
    when no suitable shell is found so callers can degrade gracefully.
    """
    if not _IS_WINDOWS:
        return None
    shell = _git_bash_from_git() or _git_bash_from_known_locations()
    if shell is None:
        # Last resort: a bash on PATH that is not the WSL shim.
        found = shutil.which("bash")
        if found and not _looks_like_wsl(Path(found)):
            shell = Path(found)
    return shell


def _to_shell_arg(script: Path) -> str:
    """Render *script* for a bash argv, using forward slashes on Windows.

    Git Bash accepts a Windows path with forward slashes (``C:/a/b.sh``);
    backslashes would be treated as escapes.
    """
    text = str(script)
    return text.replace("\\", "/") if _IS_WINDOWS else text


def run_shell_script(
    script: Path,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a POSIX shell script, cross-platform.

    On Unix the script is executed directly (shebang). On Windows it is run
    through Git Bash. Raises :class:`FileNotFoundError` when no POSIX shell is
    available on Windows — the same exception callers already handle to degrade
    the step to a non-fatal diagnostic. Output is captured and decoded as UTF-8.
    """
    if _IS_WINDOWS:
        shell = find_posix_shell()
        if shell is None:
            raise FileNotFoundError(
                "no POSIX shell found to run "
                f"{script.name}; install Git for Windows (provides Git Bash)"
            )
        argv = [str(shell), _to_shell_arg(script)]
        log.debug("Running %s via %s", script.name, shell)
    else:
        argv = [str(script)]

    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        timeout=timeout,
    )
