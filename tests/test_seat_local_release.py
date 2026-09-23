"""Package releases must not schedule or wait for VM image builds."""

from pathlib import Path

import yaml


def test_package_release_is_independent_of_seat_images() -> None:
    workflow = Path(".github/workflows/release-please.yml")
    jobs = yaml.safe_load(workflow.read_text())["jobs"]
    assert set(jobs) == {"release-please", "publish", "backmerge"}
    assert set(jobs["backmerge"]["needs"]) == {"release-please", "publish"}


def test_no_second_release_coupled_seat_builder() -> None:
    assert not Path(".github/workflows/publish-seat-image.yml").exists()


def test_publication_record_rejects_dirty_source_and_changed_disk(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    script = Path(__file__).parents[1] / "scripts/appliance/seat-build-record.py"
    (tmp_path / "seat-disk.qcow2").write_bytes(b"disk")
    (tmp_path / "seat-image-config.json").write_bytes(b"{}")
    def run(*args):
        return subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True)
    assert run("write", str(tmp_path), "--commit", "a" * 40).returncode == 0
    assert run("verify", str(tmp_path)).returncode != 0
    assert run("write", str(tmp_path), "--commit", "a" * 40, "--dirty", "0").returncode == 0
    verified = run("verify", str(tmp_path))
    assert verified.returncode == 0
    assert verified.stdout.strip() == "a" * 40
    (tmp_path / "seat-disk.qcow2").write_bytes(b"changed")
    assert run("verify", str(tmp_path)).returncode != 0


def test_publisher_refuses_substituted_tag_before_signing(tmp_path):
    import hashlib
    import json
    import subprocess
    import sys

    script = Path("scripts/appliance/seat-build-record.py").resolve()
    disk, config = b"local-disk", b"local-config"
    (tmp_path / "seat-disk.qcow2").write_bytes(disk)
    (tmp_path / "seat-image-config.json").write_bytes(config)
    def descriptor(payload, kind):
        return dict(digest="sha256:" + hashlib.sha256(payload).hexdigest(),
                    size=len(payload), mediaType="application/vnd.aptl.seat." + kind)
    manifest = dict(schemaVersion=2, mediaType="application/vnd.oci.image.manifest.v1+json",
                    config=descriptor(config, "config.v1+json"),
                    layers=[descriptor(disk, "disk.v1+qcow2")])
    path = tmp_path / "manifest.json"
    def verify(document):
        payload = json.dumps(document).encode()
        path.write_bytes(payload)
        return subprocess.run([
            sys.executable, str(script), "verify-manifest", str(tmp_path),
            "--manifest", str(path), "--manifest-digest", "sha256:" + hashlib.sha256(payload).hexdigest(),
        ], capture_output=True).returncode
    assert verify(manifest) == 0
    for target in (manifest["config"], manifest["layers"][0]):
        for field, value in (("digest", "sha256:" + "0" * 64), ("size", 999), ("mediaType", "wrong")):
            original = target[field]
            target[field] = value
            assert verify(manifest) != 0
            target[field] = original
    publish = Path("scripts/appliance/publish-seat-image.sh").read_text()
    assert publish.index("verify-manifest") < publish.index("cosign sign")
    assert 'oras tag "${namespace}@${key_digest}"' in publish
