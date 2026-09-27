"""Import and fail-closed coverage for non-POSIX seat hosts."""

from __future__ import annotations

import ast
import builtins
from pathlib import Path

import pytest

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.locking import seat_mutation_lock


@pytest.mark.parametrize(
    ("relative_path", "forbidden"),
    (
        ("src/aptl/appliance/seat/locking.py", "fcntl"),
        ("src/aptl/appliance/access_service.py", "pwd"),
    ),
)
def test_portable_modules_defer_posix_only_imports(
    relative_path: str, forbidden: str
) -> None:
    """Portable CLI collection must not import Linux-only modules eagerly."""

    source = Path(__file__).parents[1] / relative_path
    module = ast.parse(source.read_text(encoding="utf-8"))
    eager_imports = {
        alias.name.partition(".")[0]
        for statement in module.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
    } | {
        statement.module.partition(".")[0]
        for statement in module.body
        if isinstance(statement, ast.ImportFrom) and statement.module
    }

    assert forbidden not in eager_imports


def test_seat_mutation_lock_fails_closed_without_fcntl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bypassing host admission still yields a bounded launcher error."""

    real_import = builtins.__import__

    def import_without_fcntl(name: str, *args: object, **kwargs: object) -> object:
        if name == "fcntl":
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_fcntl)

    with pytest.raises(SeatLauncherError) as caught, seat_mutation_lock(tmp_path):
        pass

    assert caught.value.code == "unsupported-host-os"
