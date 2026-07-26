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
    assert "pip install --no-index" in provisioner
    assert '"aptl-labs==$APTL_APPLIANCE_VERSION"' in provisioner
    assert "docker load" not in provisioner
    assert "/opt/aptl/offline/oci-images.tar" in provisioner
    assert "install -d -m 0700 /var/lib/aptl" in provisioner
    assert "systemctl enable aptl-appliance-first-boot.service" in provisioner

    first_boot = scripts[1].read_text()
    assert "bootstrap-overlay" in first_boot
    assert "docker load" in first_boot
    assert "images-loaded" in first_boot
    assert "lab start" in first_boot
    assert "--offline-staged" in first_boot
    assert "--appliance-launch-descriptor" in first_boot
    assert "--appliance-release-public-key" in first_boot
    assert "--appliance-qualification-public-key" in first_boot


def test_first_boot_service_uses_guest_only_mutable_state() -> None:
    service = (GUEST_DIR / "aptl-appliance-first-boot.service").read_text()

    assert "After=docker.service" in service
    assert "Requires=docker.service" in service
    assert "ExecStart=/usr/local/libexec/aptl-appliance-first-boot" in service
    assert "ProtectHome=true" in service
    assert "ReadWritePaths=/var/lib/aptl /opt/aptl/project" in service


def test_appliance_guest_assets_ship_with_the_lab_distribution() -> None:
    assert "appliance" in ASSET_ROOTS
