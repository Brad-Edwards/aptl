"""Regression tests for project-wide lab lifecycle ownership (issue #905)."""

from __future__ import annotations

import multiprocessing
import os
import stat
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _hold_lifecycle_lock_in_child(project_dir: str, ready_path: str) -> None:
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock

    with lifecycle_mutation_lock(Path(project_dir)):
        Path(ready_path).write_text("ready", encoding="utf-8")
        time.sleep(30)


def test_lifecycle_mutation_lock_is_reentrant_per_thread(tmp_path: Path) -> None:
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock

    with lifecycle_mutation_lock(tmp_path):
        with lifecycle_mutation_lock(tmp_path):
            lock_path = tmp_path / ".aptl" / "lifecycle" / ".lock"
            assert lock_path.is_file()
            assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_lifecycle_lock_anchors_a_descendant_to_the_config_owner(
    tmp_path: Path,
) -> None:
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock

    (tmp_path / "aptl.json").write_text("{}", encoding="utf-8")
    descendant = tmp_path / "nested" / "working-directory"
    descendant.mkdir(parents=True)

    with lifecycle_mutation_lock(descendant) as project_root:
        assert project_root == tmp_path
        assert (tmp_path / ".aptl" / "lifecycle" / ".lock").is_file()
        assert not (descendant / ".aptl").exists()


def test_start_from_a_descendant_passes_the_config_owner_to_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.core import lab
    from aptl.core.lab_types import LabResult

    (tmp_path / "aptl.json").write_text("{}", encoding="utf-8")
    descendant = tmp_path / "nested"
    descendant.mkdir()
    observed: list[Path] = []

    def start_owned(project_dir: Path, **kwargs: object) -> LabResult:
        del kwargs
        observed.append(project_dir)
        return LabResult(success=True)

    monkeypatch.setattr(lab, "_orchestrate_lab_start_owned", start_owned)

    result = lab.orchestrate_lab_start(descendant)

    assert result.success is True
    assert observed == [tmp_path]


def test_lifecycle_mutation_lock_rejects_a_second_thread(tmp_path: Path) -> None:
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock
    from aptl.core.lifecycle_policy import LifecycleBusyError

    acquired = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with lifecycle_mutation_lock(tmp_path):
            acquired.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert acquired.wait(timeout=5)
    try:
        with pytest.raises(LifecycleBusyError, match="lifecycle owner"):
            with lifecycle_mutation_lock(tmp_path):
                pytest.fail("a second lifecycle owner must not enter")
    finally:
        release.set()
        holder.join(timeout=5)
    with lifecycle_mutation_lock(tmp_path):
        pass


def test_process_death_releases_lifecycle_ownership(tmp_path: Path) -> None:
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock
    from aptl.core.lifecycle_policy import LifecycleBusyError

    context = multiprocessing.get_context("spawn")
    ready_path = tmp_path / "child-ready"
    holder = context.Process(
        target=_hold_lifecycle_lock_in_child,
        args=(str(tmp_path), str(ready_path)),
    )
    holder.start()
    try:
        deadline = time.monotonic() + 5
        while not ready_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready_path.exists()
        with pytest.raises(LifecycleBusyError, match="lifecycle owner"):
            with lifecycle_mutation_lock(tmp_path):
                pytest.fail("the live child process must retain lifecycle ownership")
        holder.terminate()
        holder.join(timeout=5)
        assert not holder.is_alive()
        with lifecycle_mutation_lock(tmp_path):
            pass
    finally:
        if holder.is_alive():
            holder.terminate()
            holder.join(timeout=5)


def test_windows_lock_walk_rejects_a_reparse_directory_by_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aptl.core.lifecycle_guard as guard

    opened: list[tuple[int, str, bool]] = []
    closed: list[int] = []

    monkeypatch.setattr(guard, "_windows_open_root_handle", lambda project_dir: 10)

    def open_relative(parent: int, component: str, *, directory: bool) -> int:
        opened.append((parent, component, directory))
        return 11

    def reject_reparse(handle: int) -> None:
        if handle == 11:
            raise OSError("reparse")

    monkeypatch.setattr(guard, "_windows_open_relative_handle", open_relative)
    monkeypatch.setattr(guard, "_windows_reject_reparse_point", reject_reparse)
    monkeypatch.setattr(guard, "_windows_close_handle", closed.append)

    with pytest.raises(OSError, match="reparse"):
        guard._open_windows_lock_fd(tmp_path)

    assert opened == [(10, ".aptl", True)]
    assert closed == [11, 10]
    assert not (tmp_path / ".aptl").exists()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows junction semantics")
def test_windows_lock_rejects_a_junctioned_state_directory(tmp_path: Path) -> None:
    from aptl.core.lifecycle_guard import (
        LifecycleLockUnavailableError,
        lifecycle_mutation_lock,
    )

    outside = tmp_path / "outside"
    outside.mkdir()
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(tmp_path / ".aptl"), str(outside)],
        check=True,
        capture_output=True,
        text=True,
    )

    with pytest.raises(LifecycleLockUnavailableError):
        with lifecycle_mutation_lock(tmp_path):
            pytest.fail("a junctioned lifecycle root must not be followed")
    assert not (outside / "lifecycle").exists()


def test_lifecycle_mutation_lock_rejects_symlinked_state_directory(
    tmp_path: Path,
) -> None:
    from aptl.core.lifecycle_guard import (
        LifecycleLockUnavailableError,
        lifecycle_mutation_lock,
    )

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".aptl").symlink_to(outside, target_is_directory=True)

    with pytest.raises(LifecycleLockUnavailableError):
        with lifecycle_mutation_lock(tmp_path):
            pytest.fail("a symlinked lifecycle root must not be followed")


def test_start_fails_busy_before_dotenv_hydration(tmp_path: Path) -> None:
    from aptl.core.lab import orchestrate_lab_start
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock

    acquired = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with lifecycle_mutation_lock(tmp_path):
            acquired.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert acquired.wait(timeout=5)
    try:
        result = orchestrate_lab_start(tmp_path)
    finally:
        release.set()
        holder.join(timeout=5)

    assert result.success is False
    assert "lifecycle-owner-busy" in result.error
    assert "wait" in result.error.lower()
    assert not (tmp_path / ".env").exists()


def test_start_normalizes_an_unavailable_lock_path(tmp_path: Path) -> None:
    from aptl.core.lab import orchestrate_lab_start

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".aptl").symlink_to(outside, target_is_directory=True)

    result = orchestrate_lab_start(tmp_path)

    assert result.success is False
    assert "lifecycle-lock-unavailable" in result.error
    assert str(outside) not in result.error


@pytest.mark.parametrize("operation", ["stop", "kill"])
def test_destructive_operation_does_not_mutate_while_start_owner_is_alive(
    tmp_path: Path, operation: str
) -> None:
    from aptl.core.kill import kill_lab_containers
    from aptl.core.lab import stop_lab
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock

    acquired = threading.Event()
    release = threading.Event()
    backend = MagicMock()

    def hold_lock() -> None:
        with lifecycle_mutation_lock(tmp_path):
            acquired.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert acquired.wait(timeout=5)
    try:
        if operation == "stop":
            result = stop_lab(project_dir=tmp_path, backend=backend)
            assert result.success is False
            assert "lifecycle-owner-busy" in result.error
            backend.stop.assert_not_called()
        else:
            success, error = kill_lab_containers(project_dir=tmp_path, backend=backend)
            assert success is False
            assert "lifecycle-owner-busy" in error
            backend.kill.assert_not_called()
    finally:
        release.set()
        holder.join(timeout=5)


def test_full_kill_switch_does_not_clear_state_while_start_owner_is_alive(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.core import kill
    from aptl.core.lifecycle_guard import lifecycle_mutation_lock

    acquired = threading.Event()
    release = threading.Event()
    kill_processes = MagicMock()
    clear_session = MagicMock()
    monkeypatch.setattr(kill, "kill_mcp_processes", kill_processes)
    monkeypatch.setattr(kill, "clear_session", clear_session)

    def hold_lock() -> None:
        with lifecycle_mutation_lock(tmp_path):
            acquired.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert acquired.wait(timeout=5)
    try:
        result = kill.execute_kill(project_dir=tmp_path)
    finally:
        release.set()
        holder.join(timeout=5)

    assert result.success is False
    assert any("lifecycle-owner-busy" in error for error in result.errors)
    kill_processes.assert_not_called()
    clear_session.assert_not_called()
