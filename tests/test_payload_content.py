"""Payload validation inspects nested bytes and the offline wheel closure."""

import io
import tarfile

import pytest


def test_archived_common_library_retains_transitive_runtime_dependencies(
    tmp_path, monkeypatch
):
    import json
    import shutil
    import subprocess

    from aptl.appliance.inputs import _archive_project, _build_outputs

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for runtime dependency resolution")
    project = tmp_path / "source"
    common = project / "mcp/aptl-mcp-common"
    dependency = common / "node_modules/transitive-proof"
    dependency.mkdir(parents=True)
    (dependency / "index.js").write_text("module.exports = 'runtime-closure-intact';")
    (common / "package.json").write_text(
        json.dumps({"name": "aptl-mcp-common", "main": "index.js"})
    )
    (common / "index.js").write_text("module.exports = require('transitive-proof');")
    consumer = project / "mcp/mcp-red"
    (consumer / "node_modules").mkdir(parents=True)
    (consumer / "node_modules/aptl-mcp-common").symlink_to(
        common, target_is_directory=True
    )
    (consumer / "index.js").write_text("console.log(require('aptl-mcp-common'));")
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", lambda *args, **kwargs: None)
        _build_outputs(project, tmp_path)
    archive = tmp_path / "project.tar"
    _archive_project(project, archive)
    shutil.rmtree(project)
    extracted = tmp_path / "extracted"
    with tarfile.open(archive) as source:
        source.extractall(extracted, filter="data")
    result = subprocess.run(
        [node, str(extracted / "mcp/mcp-red/index.js")],
        cwd=extracted,
        env={},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "runtime-closure-intact"


def test_nested_archive_refuses_duplicate_escape_and_link_members(tmp_path):
    from aptl.appliance.payload_content import archive_files

    for names, link in [
        (("../escape",), False),
        (("same", "same"), False),
        (("safe",), True),
    ]:
        path = tmp_path / "bad.tar"
        with tarfile.open(path, "w") as archive:
            for name in names:
                info = tarfile.TarInfo(name)
                if link:
                    info.type = tarfile.SYMTYPE
                    info.linkname = "../escape"
                    archive.addfile(info)
                else:
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))
        with pytest.raises(ValueError):
            archive_files(path)


def test_wheel_closure_rejects_non_wheels_and_missing_dependencies(tmp_path):
    from aptl.appliance.payload_content import validate_wheel_closure

    (tmp_path / "aptl_labs-5.5.0-py3-none-any.whl").write_bytes(b"not a wheel")
    with pytest.raises(ValueError):
        validate_wheel_closure(
            tmp_path, "aptl-labs==5.5.0 --hash=sha256:" + "a" * 64 + "\n"
        )


def _wheel(directory, name, *, dependencies=(), python=">=3.11"):
    import hashlib
    import zipfile

    path = directory / (name.replace("-", "_") + "-1.0-py3-none-any.whl")
    metadata = (
        "Metadata-Version: 2.3\nName: "
        + name
        + "\nVersion: 1.0\nRequires-Python: "
        + python
        + "\n"
    )
    metadata += "".join(
        "Requires-Dist: " + dependency + "\n" for dependency in dependencies
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name.replace("-", "_") + "-1.0.dist-info/METADATA", metadata)
    return (
        f"{name}==1.0 --hash=sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}\n"
    )


def test_wheel_closure_proves_hashes_transitive_dependencies_and_extras(tmp_path):
    from aptl.appliance.payload_content import validate_wheel_closure

    requirement = _wheel(tmp_path, "aptl-labs", dependencies=("child[web]==1.0",))
    requirement += _wheel(
        tmp_path, "child", dependencies=('leaf==1.0; extra == "web"',)
    )
    with pytest.raises(ValueError, match="incomplete"):
        validate_wheel_closure(tmp_path, requirement)
    requirement += _wheel(tmp_path, "leaf")
    assert len(validate_wheel_closure(tmp_path, requirement)) == 3
    leaf = tmp_path / "leaf-1.0-py3-none-any.whl"
    leaf.write_bytes(leaf.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="hash-locked"):
        validate_wheel_closure(tmp_path, requirement)


def test_wheel_closure_rejects_incompatible_python(tmp_path):
    from aptl.appliance.payload_content import validate_wheel_closure

    requirement = _wheel(tmp_path, "aptl-labs", python=">=99")
    with pytest.raises(ValueError, match="Python"):
        validate_wheel_closure(tmp_path, requirement)


@pytest.mark.parametrize("architecture", ["x86_64", "aarch64"])
def test_image_archive_validates_both_docker_and_oci_layer_graphs(
    tmp_path, monkeypatch, architecture
):
    import hashlib
    import json
    import platform

    from aptl.appliance.payload_content import archive_files, docker_archive_images

    monkeypatch.setattr(platform, "machine", lambda: architecture)
    digest = lambda value: hashlib.sha256(value).hexdigest()
    layer = b"canonical layer bytes"
    config = json.dumps(
        {
            "os": "linux",
            "architecture": {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()],
            "rootfs": {"diff_ids": ["sha256:" + digest(layer)]},
        }
    ).encode()
    config_path = "blobs/sha256/" + digest(config)

    def build(oci_layer):
        layer_path = "blobs/sha256/" + digest(oci_layer)
        manifest = json.dumps(
            {
                "config": {"digest": "sha256:" + digest(config)},
                "layers": [{"digest": "sha256:" + digest(oci_layer)}],
            }
        ).encode()
        data = {
            config_path: config,
            "blobs/sha256/" + digest(layer): layer,
            layer_path: oci_layer,
            "blobs/sha256/" + digest(manifest): manifest,
            "manifest.json": json.dumps(
                [
                    {
                        "Config": config_path,
                        "RepoTags": ["example:1"],
                        "Layers": ["blobs/sha256/" + digest(layer)],
                    }
                ]
            ).encode(),
            "index.json": json.dumps(
                {"manifests": [{"digest": "sha256:" + digest(manifest)}]}
            ).encode(),
        }
        path = tmp_path / "images.tar"
        with tarfile.open(path, "w") as archive:
            for name, content in data.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return path

    path = build(layer)
    assert docker_archive_images(path, archive_files(path)) == {
        "sha256:" + digest(config): ("example:1",)
    }
    path = build(b"different validly hashed OCI layer")
    prepared_input_1 = archive_files(path)
    with pytest.raises(ValueError, match="OCI image layers differ"):
        docker_archive_images(path, prepared_input_1)
