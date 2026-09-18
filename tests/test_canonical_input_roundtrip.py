"""Exercise input staging and immutable admission with synthetic acquired bytes.

The actual packaged scenario and materializer supply the project. Small wheels,
images and build outputs replace acquisition; no image daemon or lab is started.
"""

import hashlib
import io
import json
import platform
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

import aptl
from aptl.appliance import input_images, inputs
from aptl.core.assets import materialize
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import env_pack_bundle
from aptl.validation.curated_live_proof import expected_bundle_matrix


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _image_archive(path, references):
    layer = b"fixture acquired layer"
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"diff_ids": ["sha256:" + _digest(layer)]},
        }
    ).encode()
    config_name = _digest(config) + ".json"
    manifest = json.dumps(
        [
            {
                "Config": config_name,
                "Layers": ["layer.tar"],
                "RepoTags": sorted(references.values()),
            }
        ]
    ).encode()
    with tarfile.open(path, "w") as archive:
        for name, content in {
            "manifest.json": manifest,
            config_name: config,
            "layer.tar": layer,
        }.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return "sha256:" + _digest(config)


def _build_fixture(project, work):
    for name in inputs._required_built_paths():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("fixture build output")
    for package in (project / "mcp").iterdir():
        if not (package / "package-lock.json").is_file():
            continue
        dependency = package / "node_modules/fixture-runtime/index.js"
        dependency.parent.mkdir(parents=True)
        dependency.write_text("module.exports = {};")


def _wheel_with_assets(wheelhouse, project):
    path = wheelhouse / f"aptl_labs-{aptl.__version__}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        wheel.writestr(
            f"aptl_labs-{aptl.__version__}.dist-info/METADATA",
            f"Metadata-Version: 2.3\nName: aptl-labs\nVersion: {aptl.__version__}\nRequires-Python: >=3.11\nProvides-Extra: web\n",
        )
        for asset in sorted(project.rglob("*")):
            if asset.is_file():
                wheel.write(
                    asset, "aptl/_labdata/" + asset.relative_to(project).as_posix()
                )


def test_canonical_staging_roundtrip_binds_acquired_bytes_and_rejects_tampering(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    template = tmp_path / "template"
    materialize(template)
    # New packaged assets are intentionally absent from git-ls-files until the
    # publish boundary stages them; include this source asset in the TDD tree.
    mount_source = (
        Path(__file__).resolve().parents[1] / "appliance/guest/aptl-launch.mount"
    )
    shutil.copyfile(
        mount_source,
        template / "appliance/guest/aptl-launch.mount",
    )
    # This wheel's dependency closure is deliberately empty except for itself.
    # Its immutable export is still checked against the staged requirements.
    (template / "requirements/web.txt").write_text("")
    bundle = env_pack_bundle(tmp_path / "pack")
    matrix = expected_bundle_matrix(template, AptlConfig(), bundle)
    real_references = input_images.canonical_image_references(template, bundle)
    expected_roles = inputs.HELPER_ROLES | {
        "scenario." + name for name in matrix.expected_services
    }
    assert set(real_references) == expected_roles
    assert real_references["child.shuffle-http"].startswith(
        "frikky/shuffle:http_1.4.0@sha256:"
    )
    assert all(
        reference.startswith(("aptl/", "aptl-")) or "@sha256:" in reference
        for reference in real_references.values()
    )
    assert real_references["helper.operator-access"] == (
        "aptl/operator-access-proxy:latest"
    )
    assert real_references["helper.generic-samba-ad-base"] == (
        "aptl/generic-samba-ad-base:latest"
    )
    assert real_references["helper.generic-systemd-base"] == (
        "aptl/generic-systemd-base:latest"
    )
    assert real_references["helper.generic-systemd-base-debian"] == (
        "aptl/generic-systemd-base-debian:latest"
    )
    references = {role: "fixture/" + role + ":1" for role in expected_roles}
    archive = tmp_path / "images.tar"
    image_id = _image_archive(archive, references)
    roles = {role: image_id for role in references}
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    _wheel_with_assets(wheelhouse, template)
    monkeypatch.setattr(inputs, "resolve_asset_source", lambda: (template, True))
    monkeypatch.setattr(
        inputs, "materialize", lambda project: shutil.copytree(template, project)
    )
    monkeypatch.setattr(inputs, "_build_outputs", _build_fixture)
    monkeypatch.setattr(
        input_images, "canonical_image_references", lambda *a: references
    )
    # Linux TMPDIR may be a link too; macOS uses /var -> /private/var by default.
    work_root = tmp_path / "work-root"
    work_root.mkdir()
    work_alias = tmp_path / "work-alias"
    work_alias.symlink_to(work_root, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(work_alias))
    staging = tmp_path / "staged"
    admitted = inputs.stage_canonical_inputs(
        staging=staging,
        wheelhouse=wheelhouse,
        image_archive=archive,
        image_roles=roles,
        target_python_version="3.14",
        target_architecture="x86_64",
    )
    assert admitted.scenario_pack == bundle.pack_identity
    assert set(admitted.image_roles) == expected_roles
    assert admitted.qualification == "inputs-only"
    assert admitted.python_version == "3.14"
    assert admitted.asset_lock.schema_version == "aptl.participant-asset-lock/v2"
    assert any(
        asset.source == "project/web/build/index.html"
        for asset in admitted.asset_lock.assets
    )
    with pytest.raises(ValueError, match="declared Python/architecture target"):
        inputs.validate_canonical_inputs(staging)
    first_boot = staging / "aptl-appliance-first-boot"
    original = first_boot.read_bytes()
    first_boot.write_bytes(original + b"\n# altered\n")
    with pytest.raises(ValueError, match="asset lock"):
        inputs.validate_canonical_inputs(staging, enforce_runtime_target=False)
    # Updating the top-level content lock cannot authorize a changed packaged script.
    changed = admitted.model_copy(
        update={
            "asset_lock": admitted.asset_lock.model_copy(
                update={
                    "assets": tuple(
                        asset.model_copy(
                            update={"sha256": _digest(first_boot.read_bytes())}
                        )
                        if asset.source == first_boot.name
                        else asset
                        for asset in admitted.asset_lock.assets
                    )
                }
            )
        }
    )
    (staging / "inputs.json").write_text(changed.model_dump_json())
    with pytest.raises(ValueError, match="first-boot input differs"):
        inputs.validate_canonical_inputs(staging, enforce_runtime_target=False)
