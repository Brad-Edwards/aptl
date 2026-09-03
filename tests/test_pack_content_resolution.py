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


def test_a_source_naming_no_artifact_id_is_rejected():
    """An exact artifact requirement with no resolvable identity fails closed."""

    spec = _file_spec(*_README)
    spec["source"]["artifact_requirement"]["exact_artifact"]["artifact_id"] = ""
    content, diagnostics = _resolve(spec)
    assert content is None
    assert any("pack-artifact-missing-identity" in d.message for d in diagnostics)


def test_malformed_digest_is_rejected():
    content, diagnostics = _resolve(_file_spec(_README[0], "sha256:nope", "text/markdown"))
    assert content is None
    assert any("pack-artifact-invalid-digest" in d.message for d in diagnostics)


@pytest.mark.integration
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


@pytest.mark.integration
def test_seed_extracts_a_pack_directory_tar_from_the_pack(tmp_path):
    bundle = env_pack_bundle(tmp_path / "staged", "techvault")
    content, _ = _resolve(_dir_spec(*_SRC_TAR))
    (seed,) = build_content_volume_seeds(bundle.root, (content,))
    extracted = seed.source_dir / seed.files[0].src
    assert extracted.is_dir()
    assert any(extracted.rglob("*"))  # the archive materialized real files


@pytest.mark.integration
def test_seed_fails_closed_on_declared_digest_mismatch(tmp_path):
    bundle = env_pack_bundle(tmp_path / "staged", "techvault")
    content, _ = _resolve(_file_spec(*_README))
    tampered = content.__class__(
        **{**content.__dict__, "artifact_digest": "sha256:" + "0" * 64}
    )
    with pytest.raises(ValueError):
        build_content_volume_seeds(bundle.root, (tampered,))


def test_image_node_content_is_admitted_without_runtime():
    """Issue #875: an image node that declares content but no other runtime.

    Content placement must route to the literal-destination (image-free) path
    for any realized node -- image-free OR image-backed -- not only nodes that
    declare a runtime. Before the fix, an image node with content but no runtime
    fell through to the legacy named-volume check and was rejected with
    'destination-without-backing-mount', so its config never reached the range.
    """
    from raes_contracts.planning import PlannedResource, RuntimeDomain

    from aptl.backends.raes_placement_realization import _realize_placement_resource
    from aptl.backends.raes_realization_model import NodeRealization
    from aptl.core.deployment.realization import DeploymentImageRealization

    target = "provision.node.aptl-otel-collector"
    node = NodeRealization(
        address=target,
        name="aptl-otel-collector",
        aliases=(),
        profiles=(),
        backend_services=(),
        container_name="aptl-otel-collector",
        services=(),
        networks=(),
        static_addresses=(),
        os="linux",
        runtime=None,  # image node with content but no other runtime
        image=DeploymentImageRealization(
            address=target,
            service_name="aptl-otel-collector",
            source_name="otel/opentelemetry-collector-contrib",
            source_version="1",
            image_ref="otel/opentelemetry-collector-contrib:1",
            mode="pull",
            policy_rule="allowed-source",
        ),
    )
    payload = {
        "content_name": "otel-config",
        "spec": {
            "type": "file",
            "path": "/etc/otelcol-contrib/config.yaml",
            "text": "service: {}\n",
        },
    }
    resource = PlannedResource(
        address="provision.content-placement.otel-config",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload=payload,
    )

    content, dataset, account, _service_index_schema, diagnostics = (
        _realize_placement_resource(
            resource, payload, target, {target: node}, Path(".")
        )
    )

    assert diagnostics == [], [d.code for d in diagnostics]
    assert content is not None
    assert content.dest_relpath.endswith("etc/otelcol-contrib/config.yaml")


# -- seed construction against a controlled pack resolver --------------------
#
# The seeds above are built from the real bundled pack. These drive the same
# builder with the resolver replaced, so the branches that decide how a resolved
# artifact becomes a seed -- tar extraction, single-file bytes, a stale rendered
# tree, and the two fail-closed refusals -- are each exercised with bytes the
# test controls.


class _StubIdentity(object):
    def __init__(self, digest):
        self.digest = digest


class _StubResolved(object):
    def __init__(self, data, digest):
        self.data = data
        self.identity = _StubIdentity(digest)


def _tar_bytes(members):
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


@pytest.fixture
def stub_pack(monkeypatch):
    """Replace the pack resolver with an in-memory ``artifact_id -> resolved`` map."""

    resolved: dict[str, _StubResolved] = {}

    def _resolve(pack_root, artifact, **kwargs):
        return resolved[artifact]

    monkeypatch.setattr("raes_env_packs.resolve_pack_artifact", _resolve)
    return resolved


def _pack_content(artifact_id, digest, *, source_kind, dest_relpath, media_type):
    from aptl.core.deployment.realization import DeploymentContentRealization

    return DeploymentContentRealization(
        address=f"provision.content.{artifact_id}",
        target_address="provision.node.fileshare",
        content_name=artifact_id,
        volume_suffix="fileshare_data",
        dest_relpath=dest_relpath,
        source_kind=source_kind,
        artifact_id=artifact_id,
        artifact_digest=digest,
        media_type=media_type,
    )


def test_a_pack_file_seed_carries_the_resolved_bytes_at_its_declared_basename(
    tmp_path, stub_pack
):
    """The seed copies the pack's bytes, never a host path the scenario named."""

    digest = "sha256:" + "a" * 64
    stub_pack["flag-generator"] = _StubResolved(b"#!/bin/sh\necho flag\n", digest)
    content = _pack_content(
        "flag-generator",
        digest,
        source_kind="pack-file",
        dest_relpath="opt/flags/generate.sh",
        media_type="text/x-shellscript",
    )

    (seed,) = build_content_volume_seeds(tmp_path, (content,))

    assert seed.volume_suffix == "fileshare_data"
    assert seed.files[0].dest == "opt/flags/generate.sh"
    rendered = seed.source_dir / seed.files[0].src
    assert rendered.read_bytes() == b"#!/bin/sh\necho flag\n"
    # Rendered under the ignored .aptl/content state tree, inside the bundle.
    assert ".aptl/content" in str(rendered)
    assert tmp_path in rendered.parents


def test_a_pack_directory_seed_extracts_the_archive_it_resolved(tmp_path, stub_pack):
    """A directory artifact is a tar, extracted (data-filtered) before seeding."""

    digest = "sha256:" + "b" * 64
    stub_pack["src-tree"] = _StubResolved(
        _tar_bytes({"app/main.py": b"print('hi')\n", "app/README": b"docs\n"}), digest
    )
    content = _pack_content(
        "src-tree",
        digest,
        source_kind="pack-directory",
        dest_relpath="opt/app",
        media_type="application/x-tar",
    )

    (seed,) = build_content_volume_seeds(tmp_path, (content,))

    extracted = seed.source_dir / seed.files[0].src
    assert (extracted / "app/main.py").read_bytes() == b"print('hi')\n"
    assert seed.files[0].dest == "opt/app"


def test_a_rebuilt_seed_does_not_inherit_the_previous_rendered_tree(
    tmp_path, stub_pack
):
    """Stale members from an earlier render must not be seeded into the range.

    The rendered tree is per-address, so re-seeding after the declared artifact
    changed would otherwise plant both the old and the new content.
    """

    digest = "sha256:" + "c" * 64
    stub_pack["src-tree"] = _StubResolved(_tar_bytes({"old.txt": b"old\n"}), digest)
    content = _pack_content(
        "src-tree",
        digest,
        source_kind="pack-directory",
        dest_relpath="opt/app",
        media_type="application/x-tar",
    )
    (first,) = build_content_volume_seeds(tmp_path, (content,))
    assert (first.source_dir / "tree/old.txt").is_file()

    stub_pack["src-tree"] = _StubResolved(_tar_bytes({"new.txt": b"new\n"}), digest)
    (second,) = build_content_volume_seeds(tmp_path, (content,))

    assert (second.source_dir / "tree/new.txt").is_file()
    assert not (second.source_dir / "tree/old.txt").exists()


def test_a_pack_seed_whose_resolved_digest_differs_from_the_pin_fails_closed(
    tmp_path, stub_pack
):
    """Defence in depth: the declared digest is re-checked before any seed runs."""

    stub_pack["flag-generator"] = _StubResolved(b"bytes", "sha256:" + "d" * 64)
    content = _pack_content(
        "flag-generator",
        "sha256:" + "e" * 64,
        source_kind="pack-file",
        dest_relpath="opt/flags/generate.sh",
        media_type="text/x-shellscript",
    )

    with pytest.raises(ValueError, match="digest mismatch"):
        build_content_volume_seeds(tmp_path, (content,))


def test_pack_content_declaring_no_artifact_identity_fails_closed(tmp_path):
    """Without an id + digest there is nothing to resolve or verify."""

    from aptl.core.credentials import PathContainmentError
    from aptl.core.deployment.realization import DeploymentContentRealization

    content = DeploymentContentRealization(
        address="provision.content.nameless",
        target_address="provision.node.fileshare",
        content_name="nameless",
        volume_suffix="fileshare_data",
        dest_relpath="opt/x",
        source_kind="pack-file",
    )

    with pytest.raises(PathContainmentError, match="no artifact identity"):
        build_content_volume_seeds(tmp_path, (content,))
