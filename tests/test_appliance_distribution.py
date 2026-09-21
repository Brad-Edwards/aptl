"""Authenticated transport chunking for large appliance artifacts."""

import hashlib
import io
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aptl.appliance.distribution import (
    ApplianceDistributionError,
    _write_chunk,
    fetch_distribution_artifact,
    github_distribution_urls,
    reconstruct_distribution,
    split_distribution_artifact,
)
from aptl.appliance.download import StagedDownload


class _BoundedReader(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        assert 0 <= size <= 1024 * 1024
        return super().read(size)


def _keys(root: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate()
    private_path = root / "private.pem"
    public_path = root / "public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def test_distribution_chunks_reconstruct_authenticated_canonical_bytes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "aptl-golden.qcow2"
    source.write_bytes(b"abcdefghij")
    private_key, public_key = _keys(tmp_path)
    output = tmp_path / "transport"

    result = split_distribution_artifact(
        source=source,
        output_dir=output,
        release_id="aptl-v5.5.0-x86_64",
        manifest_digest="sha256:" + "a" * 64,
        private_key=private_key,
        chunk_size=4,
    )
    reconstructed = reconstruct_distribution(
        index_path=result.index_path,
        signature_path=result.signature_path,
        chunks_dir=output,
        public_key=public_key,
        output=tmp_path / "reconstructed.qcow2",
    )

    assert reconstructed.read_bytes() == source.read_bytes()
    assert [chunk.size_bytes for chunk in result.index.chunks] == [4, 4, 2]


def test_distribution_reconstruction_rejects_tampered_chunk(tmp_path: Path) -> None:
    source = tmp_path / "payload.tar"
    source.write_bytes(b"abcdefghij")
    private_key, public_key = _keys(tmp_path)
    output = tmp_path / "transport"
    result = split_distribution_artifact(
        source=source,
        output_dir=output,
        release_id="aptl-v5.5.0-x86_64",
        manifest_digest="sha256:" + "b" * 64,
        private_key=private_key,
        chunk_size=4,
    )
    tampered = output / result.index.chunks[1].name
    tampered.chmod(0o600)
    tampered.write_bytes(b"evil")

    with pytest.raises(ApplianceDistributionError, match="chunk identity"):
        reconstruct_distribution(
            index_path=result.index_path,
            signature_path=result.signature_path,
            chunks_dir=output,
            public_key=public_key,
            output=tmp_path / "reconstructed.tar",
        )

    assert not (tmp_path / "reconstructed.tar").exists()


def test_distribution_chunk_writer_uses_bounded_streaming_reads(tmp_path: Path) -> None:
    payload = b"a" * (2 * 1024 * 1024 + 1)
    artifact_hash = hashlib.sha256()

    digest, size = _write_chunk(
        tmp_path / "chunk",
        _BoundedReader(payload),
        chunk_size=len(payload),
        artifact_hash=artifact_hash,
    )

    assert size == len(payload)
    assert digest == f"sha256:{hashlib.sha256(payload).hexdigest()}"
    assert artifact_hash.hexdigest() == hashlib.sha256(payload).hexdigest()


def test_distribution_fetch_downloads_every_authenticated_chunk(
    tmp_path: Path,
) -> None:
    source = tmp_path / "aptl-golden.qcow2"
    source.write_bytes(b"qualified-appliance-bytes")
    private_key, public_key = _keys(tmp_path)
    transport = tmp_path / "transport"
    built = split_distribution_artifact(
        source=source,
        output_dir=transport,
        release_id="aptl-v5.5.0-x86_64",
        manifest_digest="sha256:" + "c" * 64,
        private_key=private_key,
        chunk_size=7,
    )
    metadata = {
        "https://example.test/release/disk.distribution.json": (
            built.index_path.read_bytes()
        ),
        "https://example.test/release/disk.distribution.sig.json": (
            built.signature_path.read_bytes()
        ),
    }
    requested: list[str] = []

    def fetch(url: str, *, max_bytes: int) -> bytes:
        assert len(metadata[url]) <= max_bytes
        return metadata[url]

    def stage(**kwargs) -> StagedDownload:
        requested.append(kwargs["url"])
        source_chunk = transport / kwargs["filename"]
        destination = kwargs["cache_dir"] / kwargs["sha256"].split(":", 1)[1]
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / kwargs["filename"]
        shutil.copyfile(source_chunk, path)
        return StagedDownload(
            path=path,
            sha256=kwargs["sha256"],
            size_bytes=kwargs["size_bytes"],
            reused=False,
        )

    output = tmp_path / "consumer" / source.name
    fetched = fetch_distribution_artifact(
        index_url="https://example.test/release/disk.distribution.json",
        signature_url="https://example.test/release/disk.distribution.sig.json",
        chunks_base_url="https://example.test/release/",
        expected_release_id="aptl-v5.5.0-x86_64",
        cache_dir=tmp_path / "cache",
        public_key=public_key,
        output=output,
        fetch_metadata=fetch,
        stage_artifact=stage,
    )

    assert fetched.read_bytes() == source.read_bytes()
    assert requested == [
        f"https://example.test/release/{chunk.name}" for chunk in built.index.chunks
    ]
    assert not list((tmp_path / "cache").glob(".assembly-*"))


def test_distribution_fetch_rejects_wrong_selected_release(tmp_path: Path) -> None:
    source = tmp_path / "payload.tar"
    source.write_bytes(b"payload")
    private_key, public_key = _keys(tmp_path)
    transport = tmp_path / "transport"
    built = split_distribution_artifact(
        source=source,
        output_dir=transport,
        release_id="aptl-v5.5.0-x86_64",
        manifest_digest="sha256:" + "d" * 64,
        private_key=private_key,
        chunk_size=4,
    )
    metadata = iter([built.index_path.read_bytes(), built.signature_path.read_bytes()])

    with pytest.raises(ApplianceDistributionError, match="release identity"):
        fetch_distribution_artifact(
            index_url="https://example.test/release/index.json",
            signature_url="https://example.test/release/index.sig.json",
            chunks_base_url="https://example.test/release/",
            expected_release_id="aptl-v5.6.0-x86_64",
            cache_dir=tmp_path / "cache",
            public_key=public_key,
            output=tmp_path / source.name,
            fetch_metadata=lambda _url, **_kwargs: next(metadata),
        )


def test_github_distribution_urls_select_an_anonymous_version() -> None:
    index, signature, base = github_distribution_urls(
        repository="Brad-Edwards/aptl",
        tag="v5.5.0",
        artifact_name="aptl-golden.qcow2",
    )

    assert base == "https://github.com/Brad-Edwards/aptl/releases/download/v5.5.0/"
    assert index == base + "aptl-golden.qcow2.distribution.json"
    assert signature == base + "aptl-golden.qcow2.distribution.sig.json"
