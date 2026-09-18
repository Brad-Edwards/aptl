"""Tests for deterministic, closed offline appliance payloads."""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from aptl.appliance import inputs
from aptl.appliance.offline import OfflinePayloadError, build_offline_payload


def _staging(root: Path) -> Path:
    staging = root / "staging"
    wheelhouse = staging / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "aptl_labs-5.1.1-py3-none-any.whl").write_bytes(b"wheel")
    (wheelhouse / "pydantic-2-py3-none-any.whl").write_bytes(b"dependency")
    (staging / "project.tar").write_bytes(b"tracked project assets")
    (staging / "oci-images.tar").write_bytes(b"docker save output")
    (staging / "appliance-release.env").write_text(
        "APTL_APPLIANCE_SCENARIO=techvault-attacker-target\n"
        "APTL_APPLIANCE_VERSION=5.1.1\n"
    )
    (staging / "aptl-appliance-first-boot").write_text("#!/bin/sh\nset -eu\n")
    (staging / "aptl-appliance-first-boot.service").write_text("[Unit]\n")
    (staging / "aptl-launch.mount").write_text("[Mount]\n")
    return staging


def _canonical_system_packages(staging: Path) -> None:
    packages = staging / "system-packages"
    packages.mkdir()
    (packages / "docker.io_1_amd64.deb").write_bytes(b"docker")
    digest = __import__("hashlib").sha256(b"docker").hexdigest()
    (staging / "system-packages.sha256").write_text(
        f"{digest}  docker.io_1_amd64.deb\n"
    )
    (staging / "requirements.txt").write_text("aptl-labs==5.1.1\n")


def test_offline_payload_is_byte_reproducible_and_read_only(tmp_path: Path) -> None:
    staging = _staging(tmp_path)
    first = build_offline_payload(staging, tmp_path / "first.tar")
    second = build_offline_payload(staging, tmp_path / "second.tar")

    assert first.sha256 == second.sha256
    assert first.size_bytes == second.size_bytes
    assert (tmp_path / "first.tar").read_bytes() == (
        tmp_path / "second.tar"
    ).read_bytes()
    assert (tmp_path / "first.tar").stat().st_mode & 0o777 == 0o444
    with tarfile.open(tmp_path / "first.tar", "r:") as archive:
        names = archive.getnames()
        assert names == sorted(names)
        assert all(member.uid == member.gid == 0 for member in archive.getmembers())
        assert all(member.mtime == 0 for member in archive.getmembers())


def test_offline_payload_supports_locked_wheel_names_beyond_ustar(
    tmp_path: Path,
) -> None:
    staging = _staging(tmp_path)
    wheel_name = "dependency-1.0-" + "x" * 100 + ".whl"
    (staging / "wheelhouse" / wheel_name).write_bytes(b"dependency")

    result = build_offline_payload(staging, tmp_path / "long-wheel.tar")

    with tarfile.open(result.output_path, "r:") as archive:
        assert f"wheelhouse/{wheel_name}" in archive.getnames()


def test_offline_payload_rejects_unknown_files_invalid_env_and_symlinks(
    tmp_path: Path,
) -> None:
    staging = _staging(tmp_path)
    (staging / ".env").write_text("SECRET=value\n")
    with pytest.raises(OfflinePayloadError, match="unexpected"):
        build_offline_payload(staging, tmp_path / "unknown.tar")

    (staging / ".env").unlink()
    (staging / "appliance-release.env").write_text("MODEL_API_KEY=secret\n")
    with pytest.raises(OfflinePayloadError, match="release environment"):
        build_offline_payload(staging, tmp_path / "env.tar")

    (staging / "appliance-release.env").write_text(
        "APTL_APPLIANCE_SCENARIO=techvault-attacker-target\n"
        "APTL_APPLIANCE_VERSION=5.1.1\n"
    )
    (staging / "wheelhouse/link.whl").symlink_to(
        staging / "wheelhouse/aptl_labs-5.1.1-py3-none-any.whl"
    )
    with pytest.raises(OfflinePayloadError, match="symlink"):
        build_offline_payload(staging, tmp_path / "symlink.tar")


def test_offline_payload_never_overwrites_a_published_artifact(
    tmp_path: Path,
) -> None:
    staging = _staging(tmp_path)
    output = tmp_path / "payload.tar"
    output.write_bytes(b"published")

    with pytest.raises(OfflinePayloadError, match="already exists"):
        build_offline_payload(staging, output)
    assert output.read_bytes() == b"published"


def test_offline_payload_requires_one_aptl_wheel_matching_version(
    tmp_path: Path,
) -> None:
    staging = _staging(tmp_path)
    (staging / "wheelhouse/aptl_labs-5.2.0-py3-none-any.whl").write_bytes(b"other")

    with pytest.raises(OfflinePayloadError, match="exactly one matching"):
        build_offline_payload(staging, tmp_path / "duplicate.tar")


def test_canonical_payload_admits_only_locked_system_packages(tmp_path: Path) -> None:
    staging = _staging(tmp_path)
    _canonical_system_packages(staging)
    (staging / "inputs.json").write_text("{}")

    with pytest.raises(OfflinePayloadError, match="canonical payload"):
        build_offline_payload(staging, tmp_path / "canonical.tar")

    (staging / "system-packages/extra.deb").write_bytes(b"extra")
    with pytest.raises(OfflinePayloadError, match="canonical payload"):
        build_offline_payload(staging, tmp_path / "extra.tar")


def test_archive_roles_use_saved_config_ids_not_docker_store_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry_ref = "example/remote@sha256:" + "a" * 64
    references = {
        "scenario.local": "example/local:latest",
        "scenario.remote": registry_ref,
    }
    images = {
        "sha256:" + "b" * 64: ("example/local:latest",),
        "sha256:" + "c" * 64: (),
    }
    monkeypatch.setattr(
        inputs,
        "registry_image_id",
        lambda *_args, **_kwargs: "sha256:" + "c" * 64,
    )

    assert inputs._resolve_archive_image_roles(
        references, images, tmp_path / "images.tar", {}
    ) == {
        "scenario.local": "sha256:" + "b" * 64,
        "scenario.remote": "sha256:" + "c" * 64,
    }


def test_archive_roles_reject_an_ambiguous_saved_tag(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing or ambiguous"):
        inputs._resolve_archive_image_roles(
            {"scenario.local": "example/local:latest"},
            {
                "sha256:" + "b" * 64: ("example/local:latest",),
                "sha256:" + "c" * 64: ("example/local:latest",),
            },
            tmp_path / "images.tar",
            {},
        )
