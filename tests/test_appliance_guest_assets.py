"""Structural gates for the offline guest provisioning assets."""

from __future__ import annotations

import subprocess
import os
import shlex
from pathlib import Path

import pytest

from aptl._asset_manifest import ASSET_ROOTS

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUEST_DIR = PROJECT_ROOT / "appliance" / "guest"


def test_guest_scripts_are_valid_and_have_no_network_install_path() -> None:
    scripts = (
        GUEST_DIR / "provision-offline.sh",
        GUEST_DIR / "aptl-appliance-first-boot",
        GUEST_DIR / "scan-golden.sh",
    )
    for script in scripts:
        subprocess.run(["sh", "-n", str(script)], check=True)
        text = script.read_text()
        assert "curl " not in text
        assert "wget " not in text
        assert "apt-get update" not in text
        assert "docker pull" not in text
        assert "npm " not in text

    provisioner = scripts[0].read_text()
    assert 'PYTHONPATH="$1" python3 -m pip' in provisioner
    assert "wheelhouse/pip-*.whl" in provisioner
    assert "pip install --no-index" in provisioner
    assert "--target /opt/aptl/python" in provisioner
    assert "--ignore-installed" in provisioner
    assert "--break-system-packages" not in provisioner
    assert "--require-hashes" in provisioner
    assert "--only-binary=:all:" in provisioner
    assert '-r "$payload_dir/requirements.txt"' in provisioner
    assert "PYTHONPATH=/opt/aptl/python exec /usr/bin/python3" in provisioner
    assert "/usr/local/bin/aptl-misp-suricata-sync" in provisioner
    assert "/usr/local/bin/aptl appliance validate-inputs" in provisioner
    assert "system-packages.sha256" in provisioner
    assert "sha256sum --check --strict" in provisioner
    assert 'dpkg --unpack "$payload_dir"/system-packages/*.deb' in provisioner
    assert "dpkg --configure --pending" in provisioner
    assert "policy-rc.d" in provisioner
    assert "systemctl enable docker.service" in provisioner
    assert "docker load" not in provisioner
    assert "/opt/aptl/offline/oci-images.tar" in provisioner
    assert "install -d -m 0711 /var/lib/aptl" in provisioner
    assert "useradd --system --no-create-home" in provisioner
    assert "install -d -m 0700 -o aptl-mcp -g aptl-mcp" in provisioner
    assert "systemctl enable aptl-appliance-first-boot.service" in provisioner
    assert 'rm -rf "$stage"' in provisioner

    scanner = scripts[2].read_text()
    assert "for executable in docker node python3 systemctl sshd" in scanner
    assert "docker buildx version" in scanner
    assert "docker compose version" in scanner
    assert "test -x /opt/aptl/python/bin/aptl" in scanner
    assert "/usr/local/bin/aptl --version" in scanner
    assert "su -s /bin/sh -c" in scanner
    assert "test -r /opt/aptl/project/mcp/mcp-red/build/index.js" in scanner
    assert "/var/lib/cloud/instances" in scanner
    assert "/opt/aptl-stage" in scanner
    assert "/opt/aptl/offline/oci-images.tar" in scanner
    assert ".docker/config.json" in scanner
    assert "test -d /var/lib/aptl/mcp" in scanner
    assert "! -name mcp" in scanner

    first_boot = scripts[1].read_text()
    assert "/usr/local/bin/aptl appliance bootstrap-overlay" in first_boot
    assert "docker load" in first_boot
    assert "images-loaded" in first_boot
    assert "lab start" in first_boot
    assert "--offline-staged" in first_boot
    assert "--appliance-launch-descriptor" in first_boot
    assert "--appliance-release-public-key" in first_boot
    assert "--appliance-qualification-public-key" in first_boot
    assert "/usr/local/bin/aptl appliance proxy-loopback" in first_boot
    assert 'set -- "$@" --candidate-trust' in first_boot
    assert "set -- /usr/local/bin/aptl lab start" in first_boot
    assert "exec aptl lab start" not in first_boot


@pytest.mark.parametrize("guest_path", ["/opt/aptl", "/var/lib/aptl"])
def test_guest_directory_setup_allows_dispatcher_traversal_under_private_umask(
    tmp_path, guest_path
):
    target = tmp_path / guest_path.lstrip("/")
    previous = os.umask(0o077)
    try:
        target.mkdir(parents=True)
        for line in (GUEST_DIR / "provision-offline.sh").read_text().splitlines():
            if line.startswith("install -d "):
                argv = shlex.split(line)
                if guest_path in argv:
                    subprocess.run(
                        [*argv[: argv.index(guest_path)], str(target)], check=True
                    )
    finally:
        os.umask(previous)
    mode = target.stat().st_mode & 0o777
    assert mode & 0o001, (
        "a private child directory cannot override an inaccessible parent"
    )
    assert not mode & 0o022, "unrelated users must not be able to replace child state"


def test_guest_static_payload_is_readable_without_relaxing_runtime_state(tmp_path):
    roots = ("/opt/aptl/python", "/opt/aptl/project")
    leaves = []
    for root in roots:
        directory = tmp_path / root.lstrip("/") / "nested"
        directory.mkdir(mode=0o700, parents=True)
        leaf = directory / "module.py"
        leaf.write_text("pass\n")
        leaf.chmod(0o600)
        leaves.append(leaf)
    private = tmp_path / "overlay-identity"
    private.write_text("private")
    private.chmod(0o600)
    for line in (GUEST_DIR / "provision-offline.sh").read_text().splitlines():
        if line.startswith("chmod -R "):
            argv = shlex.split(line)
            assert all(path in roots for path in argv[3:])
            subprocess.run(
                [*argv[:3], *(str(tmp_path / path.lstrip("/")) for path in argv[3:])],
                check=True,
            )
    for leaf in leaves:
        assert leaf.stat().st_mode & 0o044 == 0o044
        assert leaf.parent.stat().st_mode & 0o055 == 0o055
        assert not leaf.stat().st_mode & 0o022
    assert private.stat().st_mode & 0o777 == 0o600


def test_guest_system_package_acquisition_is_version_and_digest_locked() -> None:
    acquisition = (
        PROJECT_ROOT / "scripts/appliance/acquire-guest-system-packages.sh"
    ).read_text()
    lock = (GUEST_DIR / "system-packages.sha256").read_text().splitlines()

    subprocess.run(
        [
            "bash",
            "-n",
            str(PROJECT_ROOT / "scripts/appliance/acquire-guest-system-packages.sh"),
        ],
        check=True,
    )
    assert "ubuntu:26.04@sha256:" in acquisition
    assert "docker.io=29.1.3-0ubuntu4.1" in acquisition
    assert "docker-buildx=0.30.1-0ubuntu1" in acquisition
    assert "docker-compose-v2=2.40.3+ds1-0ubuntu1" in acquisition
    assert "nodejs=22.22.1+dfsg+~cs22.19.15-1ubuntu1" in acquisition
    assert "openssh-server=1:10.2p1-2ubuntu3.6" in acquisition
    assert "sha256sum --check --strict" in acquisition
    assert len(lock) == 59
    assert all(len(line.split("  ", 1)[0]) == 64 for line in lock)


def test_first_boot_service_uses_guest_only_mutable_state() -> None:
    service = (GUEST_DIR / "aptl-appliance-first-boot.service").read_text()

    assert "After=docker.service" in service
    assert "Requires=docker.service" in service
    assert "ExecStart=/usr/local/libexec/aptl-appliance-first-boot" in service
    assert "Environment=HOME=/var/lib/aptl" in service
    assert "ProtectHome=true" in service
    assert "ReadWritePaths=/var/lib/aptl /opt/aptl/project" in service
    assert "Requires=run-aptl\\x2dlaunch.mount" in service
    assert "After=run-aptl\\x2dlaunch.mount" in service


def test_launch_share_mount_is_read_only_and_ordered_before_first_boot() -> None:
    mount = (GUEST_DIR / "aptl-launch.mount").read_text()

    assert "What=aptl-launch" in mount
    assert "Where=/run/aptl-launch" in mount
    assert "Type=9p" in mount
    assert "Options=trans=virtio,version=9p2000.L,ro" in mount
    assert "Before=aptl-appliance-first-boot.service" in mount


def test_appliance_guest_assets_ship_with_the_lab_distribution() -> None:
    assert "appliance" in ASSET_ROOTS
