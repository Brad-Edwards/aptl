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
    assert "--break-system-packages" not in provisioner
    assert "--require-hashes" in provisioner
    assert "--only-binary=:all:" in provisioner
    assert '-r "$payload_dir/requirements.txt"' in provisioner
    assert "PYTHONPATH=/opt/aptl/python exec /usr/bin/python3" in provisioner
    assert "/usr/local/bin/aptl-misp-suricata-sync" in provisioner
    assert "aptl appliance validate-inputs" in provisioner
    assert "docker load" not in provisioner
    assert "/opt/aptl/offline/oci-images.tar" in provisioner
    assert "install -d -m 0700 /var/lib/aptl" in provisioner
    assert "systemctl enable aptl-appliance-first-boot.service" in provisioner
    assert 'rm -rf "$stage"' in provisioner

    scanner = scripts[2].read_text()
    assert "for executable in aptl docker node python3 systemctl sshd" in scanner
    assert "test -x /opt/aptl/python/bin/aptl" in scanner
    assert "/var/lib/cloud/instances" in scanner
    assert "/opt/aptl-stage" in scanner
    assert "/opt/aptl/offline/oci-images.tar" in scanner
    assert ".docker/config.json" in scanner

    first_boot = scripts[1].read_text()
    assert "bootstrap-overlay" in first_boot
    assert "docker load" in first_boot
    assert "images-loaded" in first_boot
    assert "lab start" in first_boot
    assert "--offline-staged" in first_boot
    assert "--appliance-launch-descriptor" in first_boot
    assert "--appliance-release-public-key" in first_boot
    assert "--appliance-qualification-public-key" in first_boot
    assert "appliance proxy-loopback" in first_boot
    assert "exec aptl lab start" not in first_boot


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
