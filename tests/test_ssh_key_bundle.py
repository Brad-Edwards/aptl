"""The ssh_key_bundle generated-artifact provider + mount isolation (#875).

SSH key material is generated at standup (real keypairs, real authorized-key
projections), not shipped. A consumer receives only the outputs it selects, and a
producer_private output — the control-plane key — is generated but never
bind-mounted into any node.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from aptl.core.deployment._compose_stateful_model import _append_artifact_mounts
from aptl.core.deployment._ssh_key_bundle import realize_ssh_key_bundle
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentRealizationSpec,
    DeploymentStatefulConsumer,
)

pytestmark = pytest.mark.integration


def _output(name, path, sensitivity, disposition="consumer_selected"):
    return DeploymentGeneratedArtifactOutput(
        name=name, path=path, sensitivity=sensitivity, disposition=disposition
    )


def _artifact():
    outputs = (
        _output("operator-private-key", "operator/control-plane-key", "secret", "producer_private"),
        _output("workstation-dev-private-key", "dev-user/.ssh/id_rsa", "secret"),
        _output("workstation-dev-public-key", "dev-user/.ssh/id_rsa.pub", "public"),
        _output("workstation-pivot-private-key", "labadmin/.ssh/id_ed25519", "secret"),
        _output("target-authorized-keys", "labadmin/.ssh/authorized_keys", "restricted"),
        _output("kali-authorized-keys", "kali/.ssh/authorized_keys", "restricted"),
        _output("kali-pivot-private-key", "kali/.ssh/kali_pivot_key", "secret"),
    )
    consumers = (
        DeploymentStatefulConsumer(
            target_address="provision.node.workstation",
            node_name="workstation",
            service_name="workstation",
            mount_destination="/home",
            access_mode="read_only",
            selected_outputs=(
                "workstation-dev-private-key",
                "workstation-dev-public-key",
                "workstation-pivot-private-key",
                "target-authorized-keys",
            ),
        ),
        DeploymentStatefulConsumer(
            target_address="provision.node.kali",
            node_name="kali",
            service_name="kali",
            mount_destination="/home",
            access_mode="read_only",
            selected_outputs=("kali-authorized-keys", "kali-pivot-private-key"),
        ),
    )
    return DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.techvault-ssh-keys",
        name="techvault-ssh-keys",
        generator="ssh_key_bundle",
        lifecycle="regenerate_on_change",
        provenance="techvault:ssh-access-profile/v1",
        outputs=outputs,
        consumers=consumers,
    )


def test_provider_generates_every_declared_output_as_real_material(tmp_path):
    artifact = _artifact()
    staging = tmp_path / "ssh"
    assert realize_ssh_key_bundle(artifact, staging) is None
    for output in artifact.outputs:
        assert (staging / output.path).is_file()
    # Private keys are real OpenSSH keys with owner-only permissions.
    priv = staging / "dev-user/.ssh/id_rsa"
    assert "PRIVATE KEY" in priv.read_text()
    assert stat.S_IMODE(os.stat(priv).st_mode) == 0o600
    # authorized_keys authorizes the workstation pivot public key (so the
    # workstation->victim pivot path actually works).
    pivot_pub = (staging / "labadmin/.ssh/id_ed25519.pub").read_text().strip()
    target_authorized = (staging / "labadmin/.ssh/authorized_keys").read_text()
    assert pivot_pub in target_authorized


def test_unsupported_profile_fails_closed(tmp_path):
    artifact = _artifact()
    bad = DeploymentGeneratedArtifactRealization(
        **{**artifact.__dict__, "provenance": "some-other-profile/v9"}
    )
    assert realize_ssh_key_bundle(bad, tmp_path / "ssh") is not None


def test_producer_private_key_is_never_mounted_into_a_consumer(tmp_path):
    artifact = _artifact()
    spec = DeploymentRealizationSpec(
        profiles=(),
        nodes=(),
        networks=(),
        generated_artifacts=(artifact,),
    )
    services: dict[str, dict[str, object]] = {}
    _append_artifact_mounts(services, tmp_path, spec)
    all_sources = [
        str(mount.get("source"))
        for service in services.values()
        for mount in service["volumes"]
    ]
    # The control-plane key is producer_private: it appears in no consumer mount.
    assert not any("operator/control-plane-key" in src for src in all_sources)
    # The workstation consumer receives exactly its four selected outputs.
    ws_sources = [str(m.get("source")) for m in services["workstation"]["volumes"]]
    assert len(ws_sources) == 4
    assert any("dev-user/.ssh/id_rsa" in s for s in ws_sources)
    assert any("labadmin/.ssh/id_ed25519" in s for s in ws_sources)
    assert any("labadmin/.ssh/authorized_keys" in s for s in ws_sources)
