"""Safe, one-command installation of a public appliance release."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptl.appliance.public_install import (
    AppliancePublicInstallError,
    install_public_release,
)


def _metadata_tar() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        for name, payload in {
            "manifest.json": b"{}",
            "manifest.sig.json": b"{}",
            "SHA256SUMS": b"placeholder",
            "evidence/proof.json": b"{}",
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def test_public_release_install_is_atomic_and_stages_launcher_defaults(
    tmp_path: Path,
) -> None:
    seat_root = tmp_path / "state" / "aptl" / "seat"
    cache = tmp_path / "cache"
    release_key = tmp_path / "release.pem"
    qualification_key = tmp_path / "qualification.pem"
    release_key.write_text("release-public")
    qualification_key.write_text("qualification-public")
    fetched: list[str] = []

    def fetch_metadata(url: str, *, max_bytes: int) -> bytes:
        assert url.endswith("/aptl-v5.5.0-x86_64.metadata.tar")
        assert max_bytes >= len(_metadata_tar())
        return _metadata_tar()

    def verify_metadata(release: Path, public_key: Path):
        assert (release / "manifest.json").is_file()
        assert public_key == release_key
        return SimpleNamespace(release_id="aptl-v5.5.0-x86_64")

    def fetch_artifact(**kwargs) -> Path:
        output = kwargs["output"]
        fetched.append(output.name)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(output.name.encode())
        return output

    def verify_release(release: Path, public_key: Path, **kwargs):
        assert public_key == release_key
        assert kwargs["qualification_public_key_path"] == qualification_key
        assert (release / "artifacts" / "aptl-golden.qcow2").is_file()
        assert (release / "artifacts" / "offline-payload.tar").is_file()
        return SimpleNamespace(release_id="aptl-v5.5.0-x86_64")

    result = install_public_release(
        repository="Brad-Edwards/aptl",
        tag="v5.5.0",
        release_id="aptl-v5.5.0-x86_64",
        release_public_key=release_key,
        qualification_public_key=qualification_key,
        seat_root=seat_root,
        cache_dir=cache,
        fetch_metadata=fetch_metadata,
        fetch_artifact=fetch_artifact,
        verify_metadata=verify_metadata,
        verify_release=verify_release,
    )

    assert result.release_dir == seat_root / "launch" / "release"
    assert result.reused is False
    assert fetched == ["aptl-golden.qcow2", "offline-payload.tar"]
    assert (seat_root / "launch" / "release-public.pem").read_text() == (
        "release-public"
    )
    assert (seat_root / "launch" / "qualification-public.pem").read_text() == (
        "qualification-public"
    )


def test_public_release_install_rejects_unsafe_metadata_member(tmp_path: Path) -> None:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:") as archive:
        info = tarfile.TarInfo("../outside")
        info.size = 4
        archive.addfile(info, io.BytesIO(b"evil"))
    release_key = tmp_path / "release.pem"
    qualification_key = tmp_path / "qualification.pem"
    release_key.write_text("release-public")
    qualification_key.write_text("qualification-public")

    with pytest.raises(AppliancePublicInstallError, match="metadata archive"):
        install_public_release(
            repository="Brad-Edwards/aptl",
            tag="v5.5.0",
            release_id="aptl-v5.5.0-x86_64",
            release_public_key=release_key,
            qualification_public_key=qualification_key,
            seat_root=tmp_path / "seat",
            cache_dir=tmp_path / "cache",
            fetch_metadata=lambda *_args, **_kwargs: payload.getvalue(),
        )

    assert not (tmp_path / "outside").exists()
