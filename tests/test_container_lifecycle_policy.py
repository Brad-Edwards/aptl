"""No APTL code may start a helper or remove a container outside the one policy.

Two leaks reached a running lab through call sites that each looked fine:
helpers that relied on ``--rm`` alone survived a killed CLI unnamed and
unlabelled, and ``docker rm`` without ``-v`` orphaned anonymous volumes no
cleanup could ever attribute again. Both were repeated at every site that
started a helper or removed a container, so fixing the two that were caught
would leave the others to leak the same way.

These scan the source tree rather than the behavior, because the property is
"no site bypasses the policy", which only a whole-tree check can hold. They
read the syntax tree, not text, so a docstring or comment explaining ``--rm``
is not mistaken for a call site.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "aptl"
POLICY = SOURCE / "core" / "ephemeral_containers.py"


def _source_files() -> list[Path]:
    return sorted(path for path in SOURCE.rglob("*.py") if path != POLICY)


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Return the ids of every module, class and function docstring constant."""

    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def _string_constants(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    docstrings = _docstring_nodes(tree)
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def _docker_rm_literals(path: Path) -> list[int]:
    """Return lines of list literals that begin a ``docker rm`` argv."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.List) or len(node.elts) < 2:
            continue
        first, second = node.elts[0], node.elts[1]
        if (
            isinstance(first, ast.Constant)
            and first.value == "docker"
            and isinstance(second, ast.Constant)
            and second.value == "rm"
        ):
            lines.append(node.lineno)
    return lines


def test_the_scan_sees_the_source_tree():
    """A scan over an empty tree would pass every policy vacuously."""

    assert len(_source_files()) > 100
    assert POLICY.is_file()


def test_no_helper_relies_on_auto_remove_alone():
    """Every ``--rm`` must come from ``EphemeralContainer.run_options``.

    That is where the name and label that let a timed-out run remove its own
    helper are added. A bare ``--rm`` is a helper nothing can find again once
    its CLI is killed.
    """

    offenders = [
        f"{path.relative_to(ROOT)}:{line}"
        for path in _source_files()
        for line, value in _string_constants(path)
        if value == "--rm"
    ]

    assert offenders == [], (
        "start helper containers through EphemeralContainer instead of a bare "
        f"--rm: {offenders}"
    )


def test_no_container_is_removed_without_its_anonymous_volumes():
    """Every ``docker rm`` must be ``remove_container_command``, which adds ``-v``.

    A removal written inline is a removal that can drop the flag, and without
    it the container's anonymous volumes outlive it with nothing left that
    could attribute them to the lab.
    """

    offenders = [
        f"{path.relative_to(ROOT)}:{line}"
        for path in _source_files()
        for line in _docker_rm_literals(path)
    ]

    assert offenders == [], (
        "remove containers with remove_container_command instead of an inline "
        f"docker rm argv: {offenders}"
    )


@pytest.mark.parametrize(
    "snippet, expected",
    [
        ('cmd = ["docker", "run", "--rm", "img"]\n', 1),
        ('"""Explain why ``--rm`` is not enough."""\n', 0),
        ("# a comment about --rm\n", 0),
    ],
)
def test_the_helper_scan_counts_call_sites_not_prose(tmp_path, snippet, expected):
    """The guard must fire on code and stay quiet on explanation."""

    path = tmp_path / "sample.py"
    path.write_text(snippet, encoding="utf-8")

    found = [value for _line, value in _string_constants(path) if value == "--rm"]

    assert len(found) == expected


def test_the_removal_scan_counts_inline_argv(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text('run(["docker", "rm", "-f", cid])\n', encoding="utf-8")

    assert _docker_rm_literals(path) == [1]
