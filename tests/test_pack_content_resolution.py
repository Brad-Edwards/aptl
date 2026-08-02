"""Content resolved from a validated env-pack by identity + digest (#875).

APTL stops reading scenario content from host paths: a content placement whose
source declares an exact env-pack artifact (opaque id + ``sha256`` digest) is
lowered to a ``pack-file`` / ``pack-directory`` realization, and the backend seed
opens the bytes through ``resolve_pack_artifact`` — which byte-binds them to the
pack manifest digest — rather than resolving a path in the engine's tree. These
tests exercise the real bundled TechVault pack, so a passing seed proves the
declared bytes were resolved and digest-verified, not hand-copied.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from raes_contracts.planning import PlannedResource, RuntimeDomain

from aptl.backends.raes_content_realization import resolve_content_placement
from aptl.core.content_seed import build_content_volume_seeds
from aptl.core.scenario_bundle import env_pack_bundle

pytestmark = pytest.mark.integration

_README = (
    "techvault-misp-sync-readme",
    "sha256:07c3dee4987c47e57bc8f0333073abdc07b832a7e82136c3123577531978231b",
    "text/markdown",
)
_SRC_TAR = (
    "techvault-misp-sync-src",
    "sha256:c872e56e963934883190f7fed307116504c39d6771a528852a8b4e27682e8b91",
    "application/x-tar",
)


def _file_spec(artifact_id, digest, media_type, *, path="readme.md"):
    return {
        "type": "file",
        "target": "fileshare",
        "path": path,
        "source": {
            "name": artifact_id,
            "artifact_requirement": {
                "explicitness": "exact",
                "exact_artifact": {
                    "artifact_id": artifact_id,
                    "version": digest,
                    "digest": digest,
                    "media_type": media_type,
                },
            },
        },
    }


def _dir_spec(artifact_id, digest, media_type, *, destination="src"):
    spec = _file_spec(artifact_id, digest, media_type)
    spec.pop("path")
    spec["type"] = "directory"
    spec["destination"] = destination
    return spec


def _resource(spec):
    payload = {"content_name": "c", "spec": spec}
    return (
        PlannedResource(
            address="provision.content-placement.c",
            domain=RuntimeDomain.PROVISIONING,
            resource_type="content-placement",
            payload=payload,
        ),
        payload,
    )


def _resolve(spec):
    resource, payload = _resource(spec)
    return resolve_content_placement(
        resource=resource,
        payload=payload,
        target_address="provision.node.fileshare",
        target_service="fileshare",
        project_dir=Path("."),
    )


def test_file_source_lowers_to_a_pack_file_realization():
    content, diagnostics = _resolve(_file_spec(*_README))
    assert not diagnostics
    assert content is not None
    assert content.source_kind == "pack-file"
    assert content.artifact_id == _README[0]
    assert content.artifact_digest == _README[1]
    assert content.source_relpath is None  # no host path anywhere


def test_directory_source_lowers_to_a_pack_directory_realization():
    content, diagnostics = _resolve(_dir_spec(*_SRC_TAR))
    assert not diagnostics
    assert content is not None
    assert content.source_kind == "pack-directory"
    assert content.artifact_id == _SRC_TAR[0]


def test_directory_source_that_is_not_an_archive_is_rejected():
    content, diagnostics = _resolve(_dir_spec(_README[0], _README[1], "text/markdown"))
    assert content is None
    assert any("pack-directory-not-archive" in d.message for d in diagnostics)


def test_malformed_digest_is_rejected():
    content, diagnostics = _resolve(_file_spec(_README[0], "sha256:nope", "text/markdown"))
    assert content is None
    assert any("pack-artifact-invalid-digest" in d.message for d in diagnostics)


def test_seed_resolves_and_digest_verifies_file_bytes_from_the_pack(tmp_path):
    bundle = env_pack_bundle(tmp_path / "staged", "techvault")
    content, _ = _resolve(_file_spec(*_README))
    (seed,) = build_content_volume_seeds(bundle.root, (content,))
    rendered = seed.source_dir / seed.files[0].src
    assert rendered.is_file()
    # The rendered bytes are the pack's, digest-bound by resolve_pack_artifact.
    import hashlib

    digest = "sha256:" + hashlib.sha256(rendered.read_bytes()).hexdigest()
    assert digest == _README[1]


def test_seed_extracts_a_pack_directory_tar_from_the_pack(tmp_path):
    bundle = env_pack_bundle(tmp_path / "staged", "techvault")
    content, _ = _resolve(_dir_spec(*_SRC_TAR))
    (seed,) = build_content_volume_seeds(bundle.root, (content,))
    extracted = seed.source_dir / seed.files[0].src
    assert extracted.is_dir()
    assert any(extracted.rglob("*"))  # the archive materialized real files


def test_seed_fails_closed_on_declared_digest_mismatch(tmp_path):
    bundle = env_pack_bundle(tmp_path / "staged", "techvault")
    content, _ = _resolve(_file_spec(*_README))
    tampered = content.__class__(
        **{**content.__dict__, "artifact_digest": "sha256:" + "0" * 64}
    )
    with pytest.raises(ValueError):
        build_content_volume_seeds(bundle.root, (tampered,))
