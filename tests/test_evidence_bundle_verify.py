"""Tests for the standalone, streaming, resource-bounded bundle verifier.

Proves the happy path, that the verifier imports no APTL internals, and that it
rejects tampered digests, inventory/archive disagreement, unsafe member paths,
link members, and a member-count blow-up.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import _bundle_fixtures as fixtures  # noqa: E402

from aptl.core.evidence_bundle import BundleOptions  # noqa: E402
from aptl.core.evidence_bundle import build_evidence_bundle  # noqa: E402
from aptl.core.evidence_bundle import verify as verify_mod  # noqa: E402
from aptl.core.evidence_bundle.verify import verify_bundle  # noqa: E402


def _build(tmp_path: Path) -> tuple[Path, str]:
    run_dir = tmp_path / "run-1"
    fixtures.build_ready_to_seal_run(run_dir, run_id="run-1", evidence_count=2)
    out = tmp_path / "exports" / "run-1.tar"
    result = build_evidence_bundle(
        run_dir, "run-1", out, options=BundleOptions(projections=["jsonl"])
    )
    return out, result.root_identity


def _rewrite(src: Path, dst: Path, *, mutate=None, add=None, drop=None) -> None:
    mutate = mutate or {}
    add = add or {}
    drop = drop or set()
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(src, "r:") as source, tarfile.open(dst, "w:") as target:
        for member in source.getmembers():
            if member.name in drop:
                continue
            handle = source.extractfile(member)
            data = handle.read() if handle else b""
            data = mutate.get(member.name, data)
            info = tarfile.TarInfo(member.name)
            info.size = len(data)
            info.mtime = 0
            target.addfile(info, io.BytesIO(data))
        for name, data in add.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            target.addfile(info, io.BytesIO(data))


def _raw_tar(
    dst: Path, entries: dict[str, bytes], *, symlink: str | None = None
) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dst, "w:") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if symlink is not None:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)


class TestHappyPath:
    def test_valid_bundle_verifies(self, tmp_path: Path) -> None:
        out, root_identity = _build(tmp_path)
        report = verify_bundle(out)
        assert report.ok
        assert report.root_identity == root_identity
        assert report.seal_scope == "unsealed"
        assert report.issues == []


class TestStandalone:
    def test_verifier_imports_no_aptl_internals(self) -> None:
        source = Path(verify_mod.__file__).read_text(encoding="utf-8")
        assert "import aptl" not in source
        assert "from aptl" not in source


class TestRejections:
    def test_tampered_member_digest_is_rejected(self, tmp_path: Path) -> None:
        out, _ = _build(tmp_path)
        blob = next(
            m
            for m in tarfile.open(out, "r:").getnames()
            if m.startswith("evidence/blobs/")
        )
        tampered = tmp_path / "tampered" / "b.tar"
        _rewrite(out, tampered, mutate={blob: b"tampered-bytes"})
        report = verify_bundle(tampered)
        assert not report.ok
        assert any("digest mismatch" in issue for issue in report.issues)

    def test_extra_uninventoried_member_is_rejected(self, tmp_path: Path) -> None:
        out, _ = _build(tmp_path)
        with_extra = tmp_path / "extra" / "b.tar"
        _rewrite(out, with_extra, add={"sneaky.txt": b"surprise"})
        report = verify_bundle(with_extra)
        assert not report.ok
        assert any("not in inventory" in issue for issue in report.issues)

    def test_missing_envelope_is_rejected(self, tmp_path: Path) -> None:
        out, _ = _build(tmp_path)
        without_env = tmp_path / "noenv" / "b.tar"
        _rewrite(out, without_env, drop={"bundle.json"})
        report = verify_bundle(without_env)
        assert not report.ok
        assert any("missing bundle.json" in issue for issue in report.issues)

    def test_traversal_member_path_is_rejected(self, tmp_path: Path) -> None:
        raw = tmp_path / "evil" / "b.tar"
        _raw_tar(raw, {"../evil.txt": b"x", "bundle.json": b"{}"})
        report = verify_bundle(raw)
        assert not report.ok
        assert any("unsafe component" in issue for issue in report.issues)

    def test_symlink_member_is_rejected(self, tmp_path: Path) -> None:
        raw = tmp_path / "link" / "b.tar"
        _raw_tar(raw, {"bundle.json": b"{}"}, symlink="evil-link")
        report = verify_bundle(raw)
        assert not report.ok
        assert any("link member rejected" in issue for issue in report.issues)

    def test_member_count_bound_fires(self, tmp_path: Path, monkeypatch) -> None:
        out, _ = _build(tmp_path)
        monkeypatch.setattr(verify_mod, "_MAX_MEMBERS", 1)
        report = verify_bundle(out)
        assert not report.ok
        assert any("member count exceeds" in issue for issue in report.issues)


class TestEnvelopeStructure:
    def test_empty_envelope_object_is_rejected(self, tmp_path: Path) -> None:
        raw = tmp_path / "empty" / "b.tar"
        _raw_tar(raw, {"bundle.json": b"{}"})
        report = verify_bundle(raw)
        assert not report.ok
        assert any(
            "schema_version" in issue or "missing required" in issue
            for issue in report.issues
        )

    def test_wrong_schema_version_is_rejected(self, tmp_path: Path) -> None:
        raw = tmp_path / "wrong" / "b.tar"
        _raw_tar(raw, {"bundle.json": b'{"schema_version": "evil/v9"}'})
        report = verify_bundle(raw)
        assert not report.ok
        assert any("schema_version" in issue for issue in report.issues)

    def test_unknown_top_level_field_is_rejected(self, tmp_path: Path) -> None:
        out, _ = _build(tmp_path)
        with tarfile.open(out, "r:") as tar:
            envelope = tar.extractfile("bundle.json").read()
        import json

        doc = json.loads(envelope)
        doc["surprise"] = "extra"
        mutated = tmp_path / "unknown" / "b.tar"
        _rewrite(out, mutated, mutate={"bundle.json": json.dumps(doc).encode()})
        report = verify_bundle(mutated)
        assert not report.ok
        assert any("unknown fields" in issue for issue in report.issues)


def _mutate_envelope(out: Path, dst: Path, mutate_fn) -> None:
    import json

    with tarfile.open(out, "r:") as tar:
        doc = json.loads(tar.extractfile("bundle.json").read())
    mutate_fn(doc)
    _rewrite(out, dst, mutate={"bundle.json": json.dumps(doc).encode()})


class TestSealTrust:
    def test_self_declared_verified_seal_is_rejected(self, tmp_path: Path) -> None:
        out, _ = _build(tmp_path)
        mutated = tmp_path / "fakeseal" / "b.tar"
        _mutate_envelope(
            out,
            mutated,
            lambda doc: doc.__setitem__(
                "seal",
                {
                    "scope": "verified",
                    "root_identity": "sha256:" + "a" * 64,
                    "verifier_id": "x",
                },
            ),
        )
        report = verify_bundle(mutated)
        assert not report.ok
        assert any("attestation" in issue for issue in report.issues)


class TestInventoryPathInjection:
    def test_control_char_in_inventory_path_is_rejected(self, tmp_path: Path) -> None:
        out, _ = _build(tmp_path)
        mutated = tmp_path / "inject" / "b.tar"

        def _inject(doc):
            doc["inventory"][0]["bundle_path"] = "evidence/\x1b[31mevil"

        _mutate_envelope(out, mutated, _inject)
        report = verify_bundle(mutated)
        assert not report.ok
        assert any("control character" in issue for issue in report.issues)


class TestSharedBlobExport:
    def test_run_with_a_shared_blob_exports_and_verifies(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        shared = b'{"event": "shared"}\n'
        fixtures.write_evidence(
            run_dir,
            run_id="run-1",
            blob_bytes=shared,
            requirement_id="req-a",
            capture_spec_id="spec-a",
        )
        fixtures.write_evidence(
            run_dir,
            run_id="run-1",
            blob_bytes=shared,
            requirement_id="req-b",
            capture_spec_id="spec-b",
        )
        out = tmp_path / "exports" / "b.tar"
        result = build_evidence_bundle(
            run_dir, "run-1", out, options=BundleOptions(projections=["jsonl"])
        )
        report = verify_bundle(out)
        assert report.ok, report.issues
        assert result.archive.member_count >= 1
