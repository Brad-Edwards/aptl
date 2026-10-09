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

import stat

import aptl.utils.pathsafe as pathsafe
from aptl.utils.pathsafe import (
    PathContainmentError,
    create_exclusive_nofollow,
    listdir_contained_nofollow,
    open_contained_nofollow,
    read_contained_nofollow,
    remove_contained_nofollow,
    replace_private_nofollow,
)


class TestListdirContainedNofollow:
    def test_lists_sorted_entries_of_a_contained_dir(self, tmp_path):
        (tmp_path / "records").mkdir()
        (tmp_path / "records" / "b.json").write_bytes(b"{}")
        (tmp_path / "records" / "a.json").write_bytes(b"{}")

        assert listdir_contained_nofollow(tmp_path, "records") == ["a.json", "b.json"]

    def test_rejects_a_symlinked_directory_component(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.json").write_bytes(b"{}")
        (tmp_path / "records").symlink_to(outside)

        with pytest.raises(PathContainmentError) as excinfo:
            listdir_contained_nofollow(tmp_path, "records")
        assert excinfo.value.reason == "symlink"

    def test_missing_dir_raises_not_found(self, tmp_path):
        with pytest.raises(PathContainmentError) as excinfo:
            listdir_contained_nofollow(tmp_path, "records")
        assert excinfo.value.reason == "not_found"

    def test_traversal_component_is_rejected(self, tmp_path):
        with pytest.raises(PathContainmentError) as excinfo:
            listdir_contained_nofollow(tmp_path, "../etc")
        assert excinfo.value.reason == "traversal"


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

    @pytest.mark.skipif(
        not (hasattr(os, "O_PATH") or hasattr(os, "O_SEARCH")),
        reason="platform cannot open a search-only directory descriptor safely",
    )
    def test_reads_through_execute_only_intermediate_directory(self, tmp_path):
        nested = tmp_path / "private-names"
        nested.mkdir()
        target = nested / "binding.json"
        target.write_bytes(b"{}")
        nested.chmod(0o111)
        try:
            assert (
                read_contained_nofollow(tmp_path, "private-names/binding.json") == b"{}"
            )
        finally:
            nested.chmod(0o700)

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


class TestCreateExclusiveNofollowDurability:
    """ADR-050: the create-once write path must write all bytes and durably
    link the new entry into its directory."""

    def test_writes_exact_bytes_at_the_top_level(self, tmp_path):
        create_exclusive_nofollow(tmp_path, "record.json", b"payload-bytes")
        assert (tmp_path / "record.json").read_bytes() == b"payload-bytes"

    def test_creates_intermediate_directories_and_writes_nested(self, tmp_path):
        create_exclusive_nofollow(tmp_path, "run/evidence/blob.bin", b"nested")
        assert (tmp_path / "run" / "evidence" / "blob.bin").read_bytes() == b"nested"

    def test_existing_leaf_raises_file_exists_unwrapped(self, tmp_path):
        (tmp_path / "x.json").write_bytes(b"already")
        with pytest.raises(FileExistsError):
            create_exclusive_nofollow(tmp_path, "x.json", b"new")
        # The create-once caller owns idempotency: the original bytes survive.
        assert (tmp_path / "x.json").read_bytes() == b"already"

    def test_large_payload_is_written_completely(self, tmp_path):
        # Larger than a typical pipe buffer, to exercise the write path with a
        # real multi-page buffer.
        data = bytes(range(256)) * 4096  # 1 MiB
        create_exclusive_nofollow(tmp_path, "big.bin", data)
        assert (tmp_path / "big.bin").read_bytes() == data

    def test_short_writes_are_looped_until_complete(self, tmp_path, monkeypatch):
        real_write = os.write

        def chunked_write(fd, buf):
            # Accept at most 7 bytes per call to force the short-write loop.
            return real_write(fd, bytes(buf)[:7])

        monkeypatch.setattr(os, "write", chunked_write)
        payload = b"this payload is definitely longer than seven bytes"
        create_exclusive_nofollow(tmp_path, "chunked.bin", payload)
        assert (tmp_path / "chunked.bin").read_bytes() == payload

    def test_a_refusal_to_make_progress_is_an_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "write", lambda fd, buf: 0)
        with pytest.raises(OSError):
            create_exclusive_nofollow(tmp_path, "stuck.bin", b"nonempty")

    def test_failed_write_strands_no_partial_final_or_temp(self, tmp_path, monkeypatch):
        # ADR-050: a partial write must never publish a half-written final file
        # or a false "exists" state; the temp inode is always cleaned up.
        import aptl.utils.pathsafe as pathsafe

        def boom(fd, data):
            raise OSError("simulated disk failure")

        monkeypatch.setattr(pathsafe, "write_all", boom)
        with pytest.raises(OSError):
            create_exclusive_nofollow(tmp_path, "rec.json", b"data")

        assert not (tmp_path / "rec.json").exists()
        # No stranded temporary publish inode remains.
        assert list(tmp_path.glob(".rec.json*")) == []

    @pytest.mark.parametrize("write_fails", [False, True])
    def test_stale_temp_collision_uses_and_cleans_retry_name(
        self, tmp_path, monkeypatch, write_fails
    ):
        import aptl.utils.pathsafe as pathsafe

        monkeypatch.setattr(pathsafe, "_TMP_COUNTER", iter((0, 1)))
        stale = tmp_path / f".record.json.{os.getpid()}.0.tmp"
        stale.write_bytes(b"stale")
        if write_fails:

            def fail_write(fd, data):
                raise OSError("simulated disk failure")

            monkeypatch.setattr(pathsafe, "write_all", fail_write)
            with pytest.raises(OSError, match="simulated disk failure"):
                create_exclusive_nofollow(tmp_path, "record.json", b"new")
            assert not (tmp_path / "record.json").exists()
        else:
            create_exclusive_nofollow(tmp_path, "record.json", b"new")
            assert (tmp_path / "record.json").read_bytes() == b"new"
        assert list(tmp_path.glob(".record.json*")) == []

    def test_parent_directory_is_fsynced(self, tmp_path):
        fsynced_modes = []
        real_fsync = os.fsync

        def recording_fsync(fd):
            fsynced_modes.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            return real_fsync(fd)

        import aptl.utils.pathsafe as pathsafe

        original = pathsafe.os.fsync
        pathsafe.os.fsync = recording_fsync
        try:
            create_exclusive_nofollow(tmp_path, "sub/record.json", b"durable")
        finally:
            pathsafe.os.fsync = original

        # Both the file (not a dir) and its containing directory were fsynced.
        assert True in fsynced_modes  # a directory fd was fsynced
        assert False in fsynced_modes  # a regular file fd was fsynced


class TestRemoveContainedNofollow:
    def test_removes_a_contained_regular_file(self, tmp_path):
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "baseline.json").write_bytes(b"{}")

        assert remove_contained_nofollow(tmp_path, "state/baseline.json") is True
        assert not (tmp_path / "state" / "baseline.json").exists()

    def test_absent_leaf_or_parent_is_not_an_error(self, tmp_path):
        (tmp_path / "state").mkdir()

        assert remove_contained_nofollow(tmp_path, "state/baseline.json") is False
        assert remove_contained_nofollow(tmp_path, "missing/baseline.json") is False

    def test_never_follows_a_symlinked_parent(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "baseline.json").write_bytes(b"keep")
        (tmp_path / "state").symlink_to(outside)

        with pytest.raises(PathContainmentError) as excinfo:
            remove_contained_nofollow(tmp_path, "state/baseline.json")

        assert excinfo.value.reason == "symlink"
        assert (outside / "baseline.json").read_bytes() == b"keep"

    def test_refuses_a_symlinked_or_non_regular_leaf(self, tmp_path):
        target = tmp_path / "target.json"
        target.write_bytes(b"keep")
        (tmp_path / "link.json").symlink_to(target)
        (tmp_path / "dir.json").mkdir()

        with pytest.raises(PathContainmentError) as link:
            remove_contained_nofollow(tmp_path, "link.json")
        with pytest.raises(PathContainmentError) as directory:
            remove_contained_nofollow(tmp_path, "dir.json")

        assert link.value.reason == "symlink"
        assert directory.value.reason == "not_regular_file"
        assert target.read_bytes() == b"keep"
        assert (tmp_path / "link.json").is_symlink()
        assert (tmp_path / "dir.json").is_dir()


class _Interrupted(BaseException):
    """Stands in for a signal or crash that stops a write part-way."""


def _interrupt(*_args, **_kwargs):
    raise _Interrupted


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes and no-follow descriptors")
class TestReplacePrivateNofollow:
    """#966: a rewritten private file is replaced whole, never written through."""

    def test_replaces_a_permissive_file_and_parent_with_private_ones(self, tmp_path):
        env = tmp_path / "state" / "env"
        env.mkdir(parents=True)
        env.chmod(0o777)
        leaf = env / "node.env"
        leaf.write_bytes(b"OLD=1\n")
        leaf.chmod(0o666)

        replace_private_nofollow(tmp_path, "state/env/node.env", b"NEW=1\n")

        assert leaf.read_bytes() == b"NEW=1\n"
        assert stat.S_IMODE(env.stat().st_mode) == 0o700
        assert stat.S_IMODE(leaf.stat().st_mode) == 0o600

    def test_creates_missing_directories_owner_only(self, tmp_path):
        replace_private_nofollow(tmp_path, "state/env/node.env", b"NEW=1\n")

        for directory in (tmp_path / "state", tmp_path / "state" / "env"):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert (tmp_path / "state" / "env" / "node.env").read_bytes() == b"NEW=1\n"

    def test_a_hard_linked_file_never_rewrites_its_other_name(self, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"keep")
        (tmp_path / "env").mkdir()
        (tmp_path / "env" / "node.env").hardlink_to(outside)

        replace_private_nofollow(tmp_path, "env/node.env", b"NEW=1\n")

        assert outside.read_bytes() == b"keep"
        assert (tmp_path / "env" / "node.env").read_bytes() == b"NEW=1\n"

    @pytest.mark.parametrize(
        ("plant", "reason"),
        [
            (lambda leaf, outside: leaf.symlink_to(outside), "symlink"),
            (lambda leaf, outside: leaf.mkdir(), "not_regular_file"),
            (lambda leaf, outside: os.mkfifo(leaf), "not_regular_file"),
        ],
        ids=["symlink", "directory", "fifo"],
    )
    def test_refuses_an_unsafe_leaf_and_leaves_it_in_place(
        self, tmp_path, plant, reason
    ):
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"keep")
        (tmp_path / "env").mkdir()
        leaf = tmp_path / "env" / "node.env"
        plant(leaf, outside)
        planted = os.lstat(leaf)

        with pytest.raises(PathContainmentError) as excinfo:
            replace_private_nofollow(tmp_path, "env/node.env", b"NEW=1\n")

        assert excinfo.value.reason == reason
        assert outside.read_bytes() == b"keep"
        assert os.lstat(leaf).st_ino == planted.st_ino
        assert list((tmp_path / "env").glob(".node.env*")) == []

    @pytest.mark.parametrize("link", ["state", "state/env"], ids=["ancestor", "parent"])
    def test_refuses_a_symlinked_directory_without_touching_its_target(
        self, tmp_path, link
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        mode = outside.stat().st_mode
        (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / link).symlink_to(outside)

        with pytest.raises(PathContainmentError) as excinfo:
            replace_private_nofollow(tmp_path, "state/env/node.env", b"NEW=1\n")

        assert excinfo.value.reason == "symlink"
        assert list(outside.iterdir()) == []
        assert outside.stat().st_mode == mode

    @pytest.mark.parametrize(
        ("name", "replacement"),
        [("geteuid", lambda: -1), ("fchmod", lambda fd, mode: None)],
        ids=["owned-by-someone-else", "mode-does-not-stick"],
    )
    def test_refuses_a_parent_that_cannot_be_made_private(
        self, tmp_path, monkeypatch, name, replacement
    ):
        (tmp_path / "env").mkdir()
        (tmp_path / "env").chmod(0o755)
        monkeypatch.setattr(pathsafe.os, name, replacement)

        with pytest.raises(PathContainmentError) as excinfo:
            replace_private_nofollow(tmp_path, "env/node.env", b"NEW=1\n")

        assert excinfo.value.reason == "not_private"
        assert list((tmp_path / "env").iterdir()) == []

    def test_a_writable_ancestor_loses_its_write_bits_before_the_write(
        self, tmp_path
    ):
        # Docker reads the file again by path; a world-writable ancestor would
        # let another user rename the directory and swap the file after it.
        state = tmp_path / "state"
        (state / "env").mkdir(parents=True)
        state.chmod(0o777)

        replace_private_nofollow(tmp_path, "state/env/node.env", b"NEW=1\n")

        assert stat.S_IMODE(state.stat().st_mode) == 0o755
        assert stat.S_IMODE((state / "env").stat().st_mode) == 0o700

    def test_a_writable_ancestor_owned_by_someone_else_is_refused(
        self, tmp_path, monkeypatch
    ):
        state = tmp_path / "state"
        (state / "env").mkdir(parents=True)
        state.chmod(0o777)
        monkeypatch.setattr(pathsafe.os, "geteuid", lambda: -1)

        with pytest.raises(PathContainmentError) as excinfo:
            replace_private_nofollow(tmp_path, "state/env/node.env", b"NEW=1\n")

        monkeypatch.undo()
        assert excinfo.value.reason == "not_private"
        assert list((state / "env").iterdir()) == []

    def test_a_leaf_swapped_for_a_symlink_mid_write_is_replaced_not_followed(
        self, tmp_path, monkeypatch
    ):
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"keep")
        write_temp = pathsafe._write_temp_leaf

        def write_then_swap(parent_fd, leaf, data):
            name = write_temp(parent_fd, leaf, data)
            os.symlink(outside, leaf, dir_fd=parent_fd)
            return name

        monkeypatch.setattr(pathsafe, "_write_temp_leaf", write_then_swap)
        replace_private_nofollow(tmp_path, "env/node.env", b"NEW=1\n")

        leaf = tmp_path / "env" / "node.env"
        assert outside.read_bytes() == b"keep"
        assert not leaf.is_symlink()
        assert leaf.read_bytes() == b"NEW=1\n"

    def test_a_directory_swapped_mid_write_keeps_the_write_in_the_opened_one(
        self, tmp_path, monkeypatch
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        restrict = pathsafe._restrict_directory

        def restrict_then_swap(dir_fd, forbidden, *, owned):
            restrict(dir_fd, forbidden, owned=owned)
            if owned:  # the leaf's parent, once it is open and private
                (tmp_path / "env").rename(tmp_path / "moved")
                (tmp_path / "env").symlink_to(outside)

        monkeypatch.setattr(pathsafe, "_restrict_directory", restrict_then_swap)
        replace_private_nofollow(tmp_path, "env/node.env", b"NEW=1\n")

        assert list(outside.iterdir()) == []
        assert (tmp_path / "moved" / "node.env").read_bytes() == b"NEW=1\n"

    @pytest.mark.parametrize(
        ("owner", "step"),
        [(pathsafe, "write_all"), (pathsafe.os, "rename")],
        ids=["while-writing", "before-rename"],
    )
    def test_an_interrupted_replacement_keeps_the_previous_file(
        self, tmp_path, monkeypatch, owner, step
    ):
        (tmp_path / "env").mkdir(mode=0o700)
        leaf = tmp_path / "env" / "node.env"
        leaf.write_bytes(b"OLD=1\n")
        monkeypatch.setattr(owner, step, _interrupt)

        with pytest.raises(_Interrupted):
            replace_private_nofollow(tmp_path, "env/node.env", b"NEW=1\n")

        monkeypatch.undo()
        assert leaf.read_bytes() == b"OLD=1\n"
        assert list((tmp_path / "env").glob(".node.env*")) == []
