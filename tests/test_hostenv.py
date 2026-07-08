"""Tests for the host + Docker environment detection layer."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

import pytest

from aptl.core import hostenv


@dataclass
class _FakeProc:
    returncode: int
    stdout: str = ""
    stderr: str = ""


# --------------------------------------------------------------------------- #
# host_os / is_* — driven by sys.platform
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("sys_platform", "expected"),
    [
        ("linux", hostenv.OS_LINUX),
        ("linux2", hostenv.OS_LINUX),
        ("darwin", hostenv.OS_MACOS),
        ("win32", hostenv.OS_WINDOWS),
        ("cygwin", hostenv.OS_UNKNOWN),
        ("freebsd13", hostenv.OS_UNKNOWN),
    ],
)
def test_host_os_mapping(monkeypatch, sys_platform, expected) -> None:
    monkeypatch.setattr(hostenv.sys, "platform", sys_platform)
    assert hostenv.host_os() == expected


def test_os_boolean_helpers(monkeypatch) -> None:
    monkeypatch.setattr(hostenv.sys, "platform", "linux")
    assert hostenv.is_linux() and not hostenv.is_macos() and not hostenv.is_windows()

    monkeypatch.setattr(hostenv.sys, "platform", "darwin")
    assert hostenv.is_macos() and not hostenv.is_linux() and not hostenv.is_windows()

    monkeypatch.setattr(hostenv.sys, "platform", "win32")
    assert hostenv.is_windows() and not hostenv.is_linux() and not hostenv.is_macos()


# --------------------------------------------------------------------------- #
# docker_mode — driven by `docker info` OperatingSystem
# --------------------------------------------------------------------------- #
def _patch_docker(monkeypatch, *, returncode=0, stdout="", stderr="", raises=None):
    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["docker", "info"]
        if raises is not None:
            raise raises
        return _FakeProc(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(hostenv.subprocess, "run", fake_run)


def test_docker_mode_desktop(monkeypatch) -> None:
    _patch_docker(monkeypatch, stdout="Docker Desktop\n")
    assert hostenv.docker_mode() == hostenv.DOCKER_DESKTOP
    assert hostenv.is_docker_desktop() is True


def test_docker_mode_linux_native(monkeypatch) -> None:
    _patch_docker(monkeypatch, stdout="Ubuntu 24.04.4 LTS\n")
    assert hostenv.docker_mode() == hostenv.DOCKER_LINUX_NATIVE
    assert hostenv.is_docker_desktop() is False


def test_docker_mode_unknown_on_nonzero(monkeypatch) -> None:
    _patch_docker(monkeypatch, returncode=1, stderr="Cannot connect to the Docker daemon")
    assert hostenv.docker_mode() == hostenv.DOCKER_UNKNOWN


def test_docker_mode_unknown_on_empty(monkeypatch) -> None:
    _patch_docker(monkeypatch, stdout="   \n")
    assert hostenv.docker_mode() == hostenv.DOCKER_UNKNOWN


def test_docker_mode_unknown_when_docker_absent(monkeypatch) -> None:
    _patch_docker(monkeypatch, raises=FileNotFoundError("docker"))
    assert hostenv.docker_mode() == hostenv.DOCKER_UNKNOWN


def test_docker_mode_unknown_on_timeout(monkeypatch) -> None:
    _patch_docker(
        monkeypatch, raises=subprocess.TimeoutExpired(cmd="docker info", timeout=15)
    )
    assert hostenv.docker_mode() == hostenv.DOCKER_UNKNOWN


# --------------------------------------------------------------------------- #
# needs_host_ownership_fix — True only for a native Linux engine
# --------------------------------------------------------------------------- #
def test_ownership_fix_only_for_linux_native(monkeypatch) -> None:
    _patch_docker(monkeypatch, stdout="Ubuntu 24.04.4 LTS")
    assert hostenv.needs_host_ownership_fix() is True


def test_ownership_fix_skipped_on_desktop(monkeypatch) -> None:
    _patch_docker(monkeypatch, stdout="Docker Desktop")
    assert hostenv.needs_host_ownership_fix() is False


def test_ownership_fix_skipped_when_unknown(monkeypatch) -> None:
    """Fail safe: never trigger a privileged fix when the engine is unknown."""
    _patch_docker(monkeypatch, raises=FileNotFoundError("docker"))
    assert hostenv.needs_host_ownership_fix() is False
