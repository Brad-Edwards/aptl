"""Tests for the shared descriptor-relative, no-follow containment helper.

ADR-047 "Authorized artifact resolution": resolving a path and checking its
prefix is not enough because a symlink can change between the check and a
later open (TOCTOU). ``aptl.utils.pathsafe`` walks an untrusted relative
path component-by-component with ``os.open(..., O_NOFOLLOW, dir_fd=...)``
(openat-style) and hands callers the ONE handle that was opened, so nothing
can be swapped underneath a check.
"""

import os

import pytest

from aptl.utils.pathsafe import (
    PathContainmentError,
    open_contained_nofollow,
    read_contained_nofollow,
)


class TestHappyPath:
    def test_reads_exact_bytes_of_a_contained_file(self, tmp_path):
        (tmp_path / "scenario.yaml").write_bytes(b"name: custom\n")

        data = read_contained_nofollow(tmp_path, "scenario.yaml")

        assert data == b"name: custom\n"

    def test_reads_a_nested_contained_file(self, tmp_path):
        nested = tmp_path / "scenarios" / "sub"
        nested.mkdir(parents=True)
        (nested / "file.txt").write_bytes(b"hello")

        data = read_contained_nofollow(tmp_path, "scenarios/sub/file.txt")

        assert data == b"hello"

    def test_open_contained_nofollow_returns_a_closeable_binary_handle(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"payload")

        handle = open_contained_nofollow(tmp_path, "f.txt")
        try:
            assert handle.read() == b"payload"
        finally:
            handle.close()
        assert handle.closed

    def test_usable_as_a_context_manager(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"payload")

        with open_contained_nofollow(tmp_path, "f.txt") as handle:
            assert handle.read() == b"payload"


class TestRejectsAbsolutePaths:
    def test_rejects_absolute_relative_path(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"x")

        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "/etc/passwd")

        assert excinfo.value.reason == "not_relative"


class TestRejectsTraversal:
    def test_rejects_dotdot_component(self, tmp_path):
        outside = tmp_path.parent / "outside-pathsafe-test.txt"
        outside.write_bytes(b"secret")
        try:
            with pytest.raises(PathContainmentError) as excinfo:
                open_contained_nofollow(tmp_path, "../outside-pathsafe-test.txt")
            assert excinfo.value.reason == "traversal"
        finally:
            outside.unlink()

    def test_rejects_dotdot_component_in_the_middle(self, tmp_path):
        (tmp_path / "sub").mkdir()
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "sub/../f.txt")
        assert excinfo.value.reason == "traversal"


class TestRejectsNulBytes:
    def test_rejects_nul_byte_in_path(self, tmp_path):
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "foo\x00bar")
        assert excinfo.value.reason == "nul_byte"


class TestRejectsEmptyComponents:
    def test_rejects_empty_string_path(self, tmp_path):
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "")
        assert excinfo.value.reason == "empty_component"

    def test_rejects_double_slash(self, tmp_path):
        (tmp_path / "foo").mkdir()
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "foo//bar")
        assert excinfo.value.reason == "empty_component"

    def test_rejects_trailing_slash(self, tmp_path):
        (tmp_path / "foo").write_bytes(b"x")
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "foo/")
        assert excinfo.value.reason == "empty_component"


class TestRejectsNonFileTargets:
    def test_rejects_directory_leaf(self, tmp_path):
        (tmp_path / "adir").mkdir()
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "adir")
        assert excinfo.value.reason == "not_regular_file"

    def test_rejects_missing_file(self, tmp_path):
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "missing.txt")
        assert excinfo.value.reason == "not_found"


class TestRejectsSymlinkedComponents:
    def test_rejects_symlinked_directory_component(self, tmp_path):
        outside_dir = tmp_path.parent / "pathsafe-outside-dir"
        outside_dir.mkdir(exist_ok=True)
        (outside_dir / "file.txt").write_bytes(b"outside contents")
        try:
            link_dir = tmp_path / "link_dir"
            link_dir.symlink_to(outside_dir, target_is_directory=True)

            with pytest.raises(PathContainmentError) as excinfo:
                open_contained_nofollow(tmp_path, "link_dir/file.txt")
            assert excinfo.value.reason == "symlink"
        finally:
            import shutil

            shutil.rmtree(outside_dir, ignore_errors=True)

    def test_rejects_symlinked_leaf(self, tmp_path):
        target = tmp_path / "target.txt"
        target.write_bytes(b"real content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path, "link.txt")
        assert excinfo.value.reason == "symlink"

    def test_symlinked_leaf_is_rejected_even_when_pointing_inside_base(self, tmp_path):
        # A symlink pointing INSIDE base_dir is still a symlink component;
        # no-follow rejects it regardless of where it ultimately points —
        # the point is TOCTOU-proofing the walk itself, not the target.
        target = tmp_path / "inside.txt"
        target.write_bytes(b"inside content")
        link = tmp_path / "inside-link.txt"
        link.symlink_to(target)

        with pytest.raises(PathContainmentError) as excinfo:
            read_contained_nofollow(tmp_path, "inside-link.txt")
        assert excinfo.value.reason == "symlink"


class TestOneOpenIsToctouProof:
    def test_handle_reads_original_bytes_even_after_the_path_is_swapped(self, tmp_path):
        target = tmp_path / "f.txt"
        target.write_bytes(b"original")

        handle = open_contained_nofollow(tmp_path, "f.txt")
        try:
            # Simulate an attacker swapping the file's contents after the
            # handle was opened but before the caller reads it. Because the
            # fd already references the original inode, the swap cannot
            # change what gets read — proving there is exactly one open.
            os.unlink(target)
            target.write_bytes(b"swapped-by-attacker")

            assert handle.read() == b"original"
        finally:
            handle.close()

    def test_read_convenience_returns_bytes_from_the_single_open(self, tmp_path):
        target = tmp_path / "f.txt"
        target.write_bytes(b"exact bytes 123")

        assert read_contained_nofollow(tmp_path, "f.txt") == b"exact bytes 123"


class TestBaseDirUnavailable:
    def test_missing_base_dir_raises_path_containment_error(self, tmp_path):
        with pytest.raises(PathContainmentError) as excinfo:
            open_contained_nofollow(tmp_path / "does-not-exist", "f.txt")
        assert excinfo.value.reason == "base_dir_unavailable"
