"""Tests for the deterministic evidence-bundle archive writer.

Uncompressed USTAR with normalized member metadata, sorted members, no-follow
one-open source reads that verify against the sealed digest/size, output placed
outside the input run tree, and create-once publication. Two builds of the same
members produce byte-identical archives; the source run is never mutated.
"""

from __future__ import annotations

import hashlib
import tarfile
from pathlib import Path

import pytest

from aptl.core.evidence_bundle.archive import (
    BundleMember,
    write_bundle_archive,
)
from aptl.core.evidence_bundle.errors import BundleError


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _run_with_source(tmp_path: Path) -> tuple[Path, bytes]:
    run_dir = tmp_path / "run-1"
    (run_dir / "evidence" / "blobs").mkdir(parents=True)
    blob = b'{"event": 1}\n'
    (run_dir / "evidence" / "blobs" / "aa").write_bytes(blob)
    return run_dir, blob


def _members(blob: bytes) -> list[BundleMember]:
    envelope = b'{"schema_version": "aptl-evidence-bundle/v1"}'
    return [
        BundleMember(
            bundle_path="evidence/blobs/aa",
            digest=_sha(blob),
            size=len(blob),
            media_type="application/octet-stream",
            source_run_relpath="evidence/blobs/aa",
        ),
        BundleMember(
            bundle_path="bundle.json",
            digest=_sha(envelope),
            size=len(envelope),
            media_type="application/json",
            content=envelope,
        ),
    ]


class TestDeterminism:
    def test_two_builds_are_byte_identical(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        members = _members(blob)

        first = write_bundle_archive(run_dir, tmp_path / "out1" / "b.tar", members)
        second = write_bundle_archive(run_dir, tmp_path / "out2" / "b.tar", members)

        assert (
            Path(first.archive_path).read_bytes()
            == Path(second.archive_path).read_bytes()
        )
        assert first.digest == second.digest

    def test_member_metadata_is_normalized(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        result = write_bundle_archive(
            run_dir, tmp_path / "out" / "b.tar", _members(blob)
        )

        with tarfile.open(result.archive_path, "r:") as tar:
            infos = tar.getmembers()
        assert [i.name for i in infos] == sorted(i.name for i in infos)
        for info in infos:
            assert info.uid == 0 and info.gid == 0
            assert info.mtime == 0
            assert info.uname == "root" and info.gname == "root"


class TestSourceIntegrity:
    def test_source_run_is_not_mutated(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        before = {
            p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file()
        }

        write_bundle_archive(run_dir, tmp_path / "out" / "b.tar", _members(blob))

        after = {
            p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file()
        }
        assert before == after  # no checksums.sha256 written back into the run

    def test_source_digest_disagreement_is_rejected(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        members = _members(blob)
        tampered = [
            m.__class__(**{**m.__dict__, "digest": _sha(b"different")})
            if m.source_run_relpath
            else m
            for m in members
        ]
        with pytest.raises(BundleError) as excinfo:
            write_bundle_archive(run_dir, tmp_path / "out" / "b.tar", tampered)
        assert "digest" in str(excinfo.value).lower()


class TestPublication:
    def test_refuses_to_overwrite_existing_output(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        out = tmp_path / "out" / "b.tar"
        members = _members(blob)
        write_bundle_archive(run_dir, out, members)
        with pytest.raises(BundleError):
            write_bundle_archive(run_dir, out, members)

    def test_refuses_output_under_the_run_tree(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        members = _members(blob)
        with pytest.raises(BundleError):
            write_bundle_archive(run_dir, run_dir / "exports" / "b.tar", members)

    def test_rejects_duplicate_bundle_paths(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        members = _members(blob)
        dup = members + [members[1]]
        with pytest.raises(BundleError):
            write_bundle_archive(run_dir, tmp_path / "out" / "b.tar", dup)


class TestOutputPermissions:
    def test_published_bundle_is_owner_read_only(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        result = write_bundle_archive(
            run_dir, tmp_path / "pub" / "b.tar", _members(blob)
        )
        mode = Path(result.archive_path).stat().st_mode & 0o777
        assert mode == 0o400

    def test_rejects_group_or_world_accessible_existing_parent(
        self, tmp_path: Path
    ) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        parent = tmp_path / "shared"
        parent.mkdir()
        parent.chmod(0o755)
        members = _members(blob)
        with pytest.raises(BundleError) as excinfo:
            write_bundle_archive(run_dir, parent / "b.tar", members)
        assert "group/other" in str(excinfo.value).lower()

    def test_rejects_symlinked_parent(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        link = tmp_path / "linkdir"
        link.symlink_to(real)
        members = _members(blob)
        with pytest.raises(BundleError):
            write_bundle_archive(run_dir, link / "b.tar", members)

    def test_created_parent_is_owner_only(self, tmp_path: Path) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        out = tmp_path / "fresh" / "b.tar"
        write_bundle_archive(run_dir, out, _members(blob))
        assert (out.parent.stat().st_mode & 0o077) == 0


class TestArchiveShape:
    def test_archive_contains_every_member_with_exact_bytes(
        self, tmp_path: Path
    ) -> None:
        run_dir, blob = _run_with_source(tmp_path)
        result = write_bundle_archive(
            run_dir, tmp_path / "out" / "b.tar", _members(blob)
        )

        with tarfile.open(result.archive_path, "r:") as tar:
            names = set(tar.getnames())
            extracted = tar.extractfile("evidence/blobs/aa")
            assert extracted is not None
            assert extracted.read() == blob
        assert names == {"evidence/blobs/aa", "bundle.json"}
