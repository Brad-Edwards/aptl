"""Tests for the shared deterministic-USTAR archive mechanics.

These primitives are generalized out of ``aptl.appliance.offline`` (per the
EXP-008 preflight "reuse or generalize only their archive mechanics") so both
the appliance offline payload and the research evidence bundle produce
byte-identical archives from identical inputs, without a second copy of the
metadata-normalization, no-follow read, or streaming-hash logic.
"""

from __future__ import annotations

import hashlib
import os
import tarfile
from pathlib import Path

import pytest

from aptl.utils.deterministic_archive import (
    deterministic_tarinfo,
    hash_file_nofollow,
    open_nofollow,
)


class TestDeterministicTarInfo:
    def test_metadata_is_normalized(self) -> None:
        info = deterministic_tarinfo("a/b.json", is_dir=False, size=7, mode=0o644)
        assert info.name == "a/b.json"
        assert info.uid == 0
        assert info.gid == 0
        assert info.uname == "root"
        assert info.gname == "root"
        assert info.mtime == 0
        assert info.mode == 0o644
        assert info.type == tarfile.REGTYPE
        assert info.size == 7

    def test_directory_member_has_zero_size(self) -> None:
        info = deterministic_tarinfo("d", is_dir=True, size=999, mode=0o755)
        assert info.type == tarfile.DIRTYPE
        assert info.size == 0
        assert info.mode == 0o755

    def test_two_infos_from_same_inputs_are_identical(self) -> None:
        a = deterministic_tarinfo("x", is_dir=False, size=3, mode=0o644)
        b = deterministic_tarinfo("x", is_dir=False, size=3, mode=0o644)
        assert a.tobuf(format=tarfile.USTAR_FORMAT) == b.tobuf(
            format=tarfile.USTAR_FORMAT
        )


class TestNoFollowReads:
    def test_open_nofollow_reads_regular_file(self, tmp_path: Path) -> None:
        target = tmp_path / "f.bin"
        target.write_bytes(b"hello world")
        with open_nofollow(target) as handle:
            assert handle.read() == b"hello world"

    def test_open_nofollow_rejects_symlink_leaf(self, tmp_path: Path) -> None:
        outside = tmp_path / "secret.txt"
        outside.write_bytes(b"sensitive")
        link = tmp_path / "link.txt"
        link.symlink_to(outside)
        with pytest.raises(OSError):
            open_nofollow(link)

    def test_hash_file_nofollow_matches_known_answer(self, tmp_path: Path) -> None:
        target = tmp_path / "f.bin"
        target.write_bytes(b"hello world")
        digest, size = hash_file_nofollow(target)
        assert digest == f"sha256:{hashlib.sha256(b'hello world').hexdigest()}"
        assert size == len(b"hello world")

    def test_hash_file_nofollow_streams_large_input(self, tmp_path: Path) -> None:
        payload = os.urandom(3 * 1024 * 1024 + 17)
        target = tmp_path / "big.bin"
        target.write_bytes(payload)
        digest, size = hash_file_nofollow(target)
        assert digest == f"sha256:{hashlib.sha256(payload).hexdigest()}"
        assert size == len(payload)
