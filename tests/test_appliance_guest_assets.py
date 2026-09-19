"""Structural gates for the offline guest provisioning assets."""

from __future__ import annotations

import subprocess
from pathlib import Path

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
    assert 'wheelhouse/pip-*.whl' in provisioner
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
    assert 'system-packages.sha256' in provisioner
    assert 'sha256sum --check --strict' in provisioner
    assert 'dpkg --unpack "$payload_dir"/system-packages/*.deb' in provisioner
    assert "dpkg --configure --pending" in provisioner
    assert "policy-rc.d" in provisioner
    assert "systemctl enable docker.service" in provisioner
    assert "docker load" not in provisioner
    assert "/opt/aptl/offline/oci-images.tar" in provisioner
    assert "install -d -m 0700 /var/lib/aptl" in provisioner
    assert "useradd --system --no-create-home" in provisioner
    assert "install -d -m 0700 -o aptl-mcp -g aptl-mcp" in provisioner
    assert "systemctl enable aptl-appliance-first-boot.service" in provisioner
    assert 'rm -rf "$stage"' in provisioner

    scanner = scripts[2].read_text()
    assert "for executable in docker node python3 systemctl sshd" in scanner
    assert "test -x /opt/aptl/python/bin/aptl" in scanner
    assert "/usr/local/bin/aptl --version" in scanner
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
    assert "nodejs=22.22.1+dfsg+~cs22.19.15-1ubuntu1" in acquisition
    assert "openssh-server=1:10.2p1-2ubuntu3.6" in acquisition
    assert "sha256sum --check --strict" in acquisition
    assert len(lock) == 57
    assert all(len(line.split("  ", 1)[0]) == 64 for line in lock)

def test_first_boot_service_uses_guest_only_mutable_state() -> None:
    service = (GUEST_DIR / "aptl-appliance-first-boot.service").read_text()

    assert "After=docker.service" in service
    assert "Requires=docker.service" in service
    assert "ExecStart=/usr/local/libexec/aptl-appliance-first-boot" in service
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
