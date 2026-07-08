"""Regression guard for host-side privilege escalation policy."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "src" / "aptl"


def _source_files() -> Iterable[Path]:
    """Return shipped Python source files that run on the host."""
    return sorted(SOURCE_ROOT.rglob("*.py"))


def _string_parts(node: ast.AST) -> list[str]:
    """Extract literal string fragments from normal and formatted strings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        ]
    return []


def _literal_tokens(node: ast.AST) -> list[str]:
    """Return literal tokens from a list or tuple command expression."""
    if not isinstance(node, ast.List | ast.Tuple):
        return []
    tokens: list[str] = []
    for element in node.elts:
        parts = _string_parts(element)
        if len(parts) == 1:
            tokens.append(parts[0])
    return tokens


def _contains_silent_sudo_command(tokens: list[str]) -> bool:
    """Return whether a literal command token list invokes sudo non-interactively."""
    return "sudo" in tokens and "-n" in tokens[tokens.index("sudo") + 1 :]


def _contains_silent_sudo_text(value: str) -> bool:
    """Return whether text contains a silent sudo invocation."""
    lines = value.splitlines() or [value]
    return any("sudo" in line and "-n" in line for line in lines)


def _display_path(path: Path) -> str:
    """Return a stable path label for failures."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _silent_escalation_violations(path: Path) -> list[str]:
    """Find literal host-side sudo non-interactive escalation patterns."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[str] = []
    for node in ast.walk(tree):
        tokens = _literal_tokens(node)
        if _contains_silent_sudo_command(tokens):
            violations.append(f"{_display_path(path)}:{node.lineno}")
            continue
        for value in _string_parts(node):
            if _contains_silent_sudo_text(value):
                violations.append(f"{_display_path(path)}:{node.lineno}")
    return violations


def test_guard_detects_sudo_dash_n_command_list(tmp_path):
    """Prove the guard fails on the historical silent escalation shape."""
    source = tmp_path / "silent.py"
    source.write_text(
        'import subprocess\nsubprocess.run(["sudo", "-n", "chown", "me:file"])\n',
        encoding="utf-8",
    )

    assert _silent_escalation_violations(source) == [f"{source}:2"]


def test_guard_detects_sudo_dash_n_shell_text(tmp_path):
    """Prove the guard fails on shell-string non-interactive sudo."""
    source = tmp_path / "silent.py"
    source.write_text(
        'import subprocess\nsubprocess.run("sudo -n chown me:file", shell=True)\n',
        encoding="utf-8",
    )

    assert _silent_escalation_violations(source) == [f"{source}:2"]


def test_shipped_source_has_no_silent_privilege_escalation():
    """Host-side aptl source must not rely on sudo non-interactively."""
    violations = [
        violation
        for source_file in _source_files()
        for violation in _silent_escalation_violations(source_file)
    ]

    assert violations == []
