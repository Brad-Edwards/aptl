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
from aptl.core.ssh import _KEY_NAME, SSHKeyResult

_MODULE = "aptl.core.deployment._ssh_key_bundle"


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


@pytest.mark.integration
def test_provider_generates_every_declared_output_as_real_material(tmp_path):
    artifact = _artifact()
    staging = tmp_path / "ssh"
    ssh_home = tmp_path / "ssh_home"  # never touch the real ~/.ssh in tests
    assert realize_ssh_key_bundle(artifact, staging, host_ssh_dir=ssh_home) is None
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
    # The producer-private control-plane key is the reused ~/.ssh operator key,
    # and its public is authorized on the targets.
    operator_pub = (ssh_home / "aptl_lab_key.pub").read_text().strip()
    assert operator_pub in target_authorized


def test_unsupported_profile_fails_closed(tmp_path):
    artifact = _artifact()
    bad = DeploymentGeneratedArtifactRealization(
        **{**artifact.__dict__, "provenance": "some-other-profile/v9"}
    )
    assert (
        realize_ssh_key_bundle(bad, tmp_path / "ssh", host_ssh_dir=tmp_path / "h")
        is not None
    )


def _with_outputs(artifact, outputs):
    """Return ``artifact`` carrying a different declared output set."""

    return DeploymentGeneratedArtifactRealization(
        **{**artifact.__dict__, "outputs": outputs}
    )


class _RecordingKeygen(object):
    """Stand-in for ``ssh-keygen`` that writes a keypair-shaped pair of files.

    The subprocess itself is ``aptl.core.ssh``'s to prove (and the integration
    test above proves the real thing end to end). Substituting it here keeps the
    derivation this module owns -- which keys get generated, which public halves
    each authorized_keys file authorizes, what happens when a step fails -- under
    test without a process launch per key.
    """

    def __init__(self, *, error="", write_public=True):
        self.error = error
        self.write_public = write_public
        self.calls = []

    def __call__(self, private_key, comment, label):
        self.calls.append((Path(private_key).name, comment))
        if self.error:
            return self.error
        private_key.write_text(
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n{comment}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        if self.write_public:
            Path(f"{private_key}.pub").write_text(f"ssh-ed25519 AAAA-{comment} {comment}\n")
        return ""


def _fake_ensure_ssh_keys(*, success=True, error=None):
    """Stand-in for the persistent control-plane key generator in ~/.ssh."""

    def _ensure(keys_dir, host_ssh_dir):
        if not success:
            return SSHKeyResult(success=False, generated=False, error=error)
        host_ssh_dir.mkdir(parents=True, exist_ok=True)
        (host_ssh_dir / _KEY_NAME).write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ncontrol-plane\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        (host_ssh_dir / f"{_KEY_NAME}.pub").write_text(
            "ssh-ed25519 AAAA-control-plane aptl-control-plane\n"
        )
        return SSHKeyResult(success=True, generated=True)

    return _ensure


@pytest.fixture
def stub_keygen(monkeypatch):
    """Install the recording keygen + control-plane stubs and hand them back."""

    keygen = _RecordingKeygen()
    monkeypatch.setattr(f"{_MODULE}._run_ssh_keygen", keygen)
    monkeypatch.setattr(f"{_MODULE}.ensure_ssh_keys", _fake_ensure_ssh_keys())
    return keygen


def test_each_authorized_keys_file_authorizes_exactly_its_declared_access_path(
    tmp_path, stub_keygen
):
    """The projections reproduce the TechVault access topology, nothing wider.

    A target authorizes the control-plane, kali-pivot and workstation-pivot keys
    (operator SSH, the kali->target attack path, the workstation->target pivot);
    kali authorizes only the control plane. A projection that authorized a key it
    should not would silently widen the range's reachable attack surface.
    """

    artifact = _artifact()
    staging = tmp_path / "ssh"

    assert realize_ssh_key_bundle(artifact, staging, host_ssh_dir=tmp_path / "h") is None

    def _pub(relpath):
        return (staging / relpath).read_text().strip()

    operator = _pub("operator/control-plane-key.pub")
    kali_pivot = _pub("kali/.ssh/kali_pivot_key.pub")
    workstation_pivot = _pub("labadmin/.ssh/id_ed25519.pub")
    dev = _pub("dev-user/.ssh/id_rsa.pub")

    target = (staging / "labadmin/.ssh/authorized_keys").read_text().splitlines()
    assert target == [operator, kali_pivot, workstation_pivot]
    kali = (staging / "kali/.ssh/authorized_keys").read_text().splitlines()
    assert kali == [operator]
    # The dev-user key is a login credential for the workstation, not something
    # any authorized_keys projection grants access with.
    assert dev not in target
    assert dev not in kali


def test_realizing_the_same_staging_root_twice_reuses_the_generated_keys(
    tmp_path, stub_keygen
):
    """Re-realization must not re-run keygen over an existing key.

    The bundle is realized once for image-free consumers and again for the
    Compose consumers. ``ssh-keygen`` refuses to overwrite an existing file
    non-interactively, so a second generation attempt would fail the run; the
    provider is idempotent instead, and the second pass must leave the key bytes
    (already mounted/authorized) untouched.
    """

    artifact = _artifact()
    staging = tmp_path / "ssh"
    assert realize_ssh_key_bundle(artifact, staging, host_ssh_dir=tmp_path / "h") is None
    first_pass_calls = len(stub_keygen.calls)
    dev_key = (staging / "dev-user/.ssh/id_rsa").read_text()

    assert realize_ssh_key_bundle(artifact, staging, host_ssh_dir=tmp_path / "h") is None

    assert first_pass_calls == 3  # dev, workstation pivot, kali pivot
    assert len(stub_keygen.calls) == first_pass_calls  # nothing regenerated
    assert (staging / "dev-user/.ssh/id_rsa").read_text() == dev_key


def test_a_keygen_failure_fails_the_bundle_closed(tmp_path, monkeypatch):
    """A failed key generation surfaces the tool's error, not a partial bundle."""

    monkeypatch.setattr(f"{_MODULE}.ensure_ssh_keys", _fake_ensure_ssh_keys())
    monkeypatch.setattr(
        f"{_MODULE}._run_ssh_keygen", _RecordingKeygen(error="ssh-keygen: no space left")
    )
    staging = tmp_path / "ssh"

    error = realize_ssh_key_bundle(_artifact(), staging, host_ssh_dir=tmp_path / "h")

    assert error == "ssh-keygen: no space left"
    # No authorized_keys was composed from a bundle that never generated its keys.
    assert not (staging / "labadmin/.ssh/authorized_keys").exists()


def test_a_failed_control_plane_key_fails_the_bundle_closed(tmp_path, monkeypatch):
    """The reused ~/.ssh control-plane key failing stops the bundle immediately."""

    monkeypatch.setattr(
        f"{_MODULE}.ensure_ssh_keys",
        _fake_ensure_ssh_keys(success=False, error="host key dir is not writable"),
    )
    keygen = _RecordingKeygen()
    monkeypatch.setattr(f"{_MODULE}._run_ssh_keygen", keygen)

    error = realize_ssh_key_bundle(_artifact(), tmp_path / "ssh", host_ssh_dir=tmp_path / "h")

    assert error == "host key dir is not writable"
    assert keygen.calls == []  # nothing generated after the first failure


def test_a_public_half_missing_when_projecting_authorized_keys_fails_closed(
    tmp_path, monkeypatch
):
    """An authorized_keys file is never written from a partially-generated bundle.

    Composing it from whatever public halves happen to exist would ship a target
    that silently does not authorize one of its declared access paths.
    """

    monkeypatch.setattr(f"{_MODULE}.ensure_ssh_keys", _fake_ensure_ssh_keys())
    monkeypatch.setattr(
        f"{_MODULE}._run_ssh_keygen", _RecordingKeygen(write_public=False)
    )
    staging = tmp_path / "ssh"

    error = realize_ssh_key_bundle(_artifact(), staging, host_ssh_dir=tmp_path / "h")

    assert error is not None
    assert "missing public key for kali-pivot-private-key" in error
    assert not (staging / "labadmin/.ssh/authorized_keys").exists()


def test_a_declared_output_the_profile_cannot_produce_fails_closed(
    tmp_path, stub_keygen
):
    """Every declared output must exist afterwards or the run fails.

    An output the profile has no producer for would otherwise be silently absent
    and the consumer's mount would bind a path Docker then creates as an empty
    directory.
    """

    artifact = _artifact()
    extended = _with_outputs(
        artifact,
        (*artifact.outputs, _output("victim-authorized-keys", "victim/.ssh/authorized_keys", "restricted")),
    )

    error = realize_ssh_key_bundle(extended, tmp_path / "ssh", host_ssh_dir=tmp_path / "h")

    assert error is not None
    assert "missing declared output(s)" in error
    assert "victim/.ssh/authorized_keys" in error


def test_a_bundle_declaring_no_control_plane_key_omits_it_from_the_projections(
    tmp_path, stub_keygen
):
    """Only declared keypairs are generated and authorized.

    The profile knows a fixed key topology, but the SDL decides which of it this
    scenario declares; an undeclared key must neither be generated nor appear in
    an authorized_keys file APTL writes.
    """

    artifact = _artifact()
    kept = tuple(
        output
        for output in artifact.outputs
        if output.name not in ("operator-private-key", "kali-pivot-private-key")
    )
    # A bundle that declares no kali projection at all writes no such file.
    no_kali_projection = tuple(
        output for output in kept if output.name != "kali-authorized-keys"
    )
    assert realize_ssh_key_bundle(
        _with_outputs(artifact, no_kali_projection),
        tmp_path / "no-kali",
        host_ssh_dir=tmp_path / "h",
    ) is None
    assert not (tmp_path / "no-kali" / "kali").exists()

    assert realize_ssh_key_bundle(
        _with_outputs(artifact, kept), tmp_path / "ssh", host_ssh_dir=tmp_path / "h"
    ) is None

    staging = tmp_path / "ssh"
    assert not (staging / "operator").exists()
    assert not (staging / "kali/.ssh/kali_pivot_key").exists()
    workstation_pivot = (staging / "labadmin/.ssh/id_ed25519.pub").read_text().strip()
    # kali's projection authorized only the (undeclared) control-plane key, so it
    # is written empty rather than falling back to some other key.
    assert (staging / "kali/.ssh/authorized_keys").read_text() == ""
    assert (
        (staging / "labadmin/.ssh/authorized_keys").read_text().splitlines()
        == [workstation_pivot]
    )


def test_a_permission_hardening_failure_fails_the_bundle_closed(tmp_path, monkeypatch):
    """A key that cannot be restricted to the host user is not shipped.

    A world-readable private key in the staging root would be bind-mounted into
    the range as-is, so the provider refuses rather than continuing.
    """

    monkeypatch.setattr(f"{_MODULE}.ensure_ssh_keys", _fake_ensure_ssh_keys())
    monkeypatch.setattr(f"{_MODULE}._run_ssh_keygen", _RecordingKeygen())
    monkeypatch.setattr(
        f"{_MODULE}._harden_private_key", lambda path: f"cannot restrict {path.name}"
    )

    error = realize_ssh_key_bundle(_artifact(), tmp_path / "ssh", host_ssh_dir=tmp_path / "h")

    assert error == "cannot restrict control-plane-key"


def test_a_scenario_key_that_cannot_be_hardened_fails_the_bundle_closed(
    tmp_path, stub_keygen, monkeypatch
):
    """The refusal covers the freshly generated scenario keys, not just the operator's."""

    monkeypatch.setattr(
        f"{_MODULE}._harden_private_key",
        lambda path: "" if path.name == "control-plane-key" else f"cannot restrict {path.name}",
    )

    error = realize_ssh_key_bundle(_artifact(), tmp_path / "ssh", host_ssh_dir=tmp_path / "h")

    assert error == "cannot restrict id_rsa"


def test_a_projection_that_cannot_be_mode_restricted_fails_closed(
    tmp_path, stub_keygen, monkeypatch
):
    """An authorized_keys file sshd would reject for its mode is not shipped.

    sshd ignores an authorized_keys file with over-permissive modes, which would
    turn a declared access path into a silent auth failure at attack time.
    """

    monkeypatch.setattr(
        f"{_MODULE}._set_public_key_mode",
        lambda path: "cannot set mode" if path.name == "authorized_keys" else "",
    )

    error = realize_ssh_key_bundle(_artifact(), tmp_path / "ssh", host_ssh_dir=tmp_path / "h")

    assert error == "cannot set mode"


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
