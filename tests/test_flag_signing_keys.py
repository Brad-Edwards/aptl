"""Realize the per-node flag-signing keys generated artifact (#875).

The scenario declares flag-signing keys as a backend-produced generated
artifact; APTL derives one key per node from a producer-private seed. These
tests pin that each declared per-node key is written and readable (so the
``aptl-flaggen`` oneshot no longer fails with "flag signing key unavailable"),
the seed stays reproducible, and derivation is stable across a re-run.
"""

from __future__ import annotations

import hashlib
import hmac

from aptl.core.deployment._flag_signing_keys import (
    FLAG_SIGNING_PROFILE_V2,
    realize_flag_signing_keys,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
)


def _artifact(provenance: str = FLAG_SIGNING_PROFILE_V2):
    return DeploymentGeneratedArtifactRealization(
        address="provision.generated.techvault-flag-signing-keys",
        name="techvault-flag-signing-keys",
        generator="rendered_config",
        lifecycle="regenerate_on_change",
        provenance=provenance,
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name="signing-seed",
                path="internal/signing-seed",
                sensitivity="secret",
                disposition="producer_private",
            ),
            DeploymentGeneratedArtifactOutput(
                name="victim-signing-key", path="victim.key", sensitivity="secret"
            ),
            DeploymentGeneratedArtifactOutput(
                name="fileshare-signing-key", path="fileshare.key", sensitivity="secret"
            ),
        ),
        consumers=(),
    )


def test_flag_signing_keys_are_generated_and_derived_from_the_seed(tmp_path):
    error = realize_flag_signing_keys(_artifact(), tmp_path)

    assert error is None
    seed_hex = (tmp_path / "internal" / "signing-seed").read_text().strip()
    seed = bytes.fromhex(seed_hex)
    for node in ("victim", "fileshare"):
        key = (tmp_path / f"{node}.key").read_text().strip()
        assert key, f"{node} key is empty"
        # The key is HMAC-SHA256(seed, node), reproducible by the scoring backend.
        assert key == hmac.new(seed, node.encode(), hashlib.sha256).hexdigest()


def test_flag_signing_seed_is_reused_on_a_second_run(tmp_path):
    realize_flag_signing_keys(_artifact(), tmp_path)
    first = (tmp_path / "victim.key").read_text()

    realize_flag_signing_keys(_artifact(), tmp_path)
    assert (tmp_path / "victim.key").read_text() == first


def test_unsupported_profile_is_refused(tmp_path):
    error = realize_flag_signing_keys(_artifact(provenance="other:profile/v1"), tmp_path)
    assert error is not None and "Unsupported" in error


def test_flag_signing_consumer_never_mounts_the_producer_private_seed():
    """A flag-signing consumer gets per-output mounts, never a whole-dir bind.

    A whole-directory bind would expose the producer-private signing seed to the
    node; the seed must stay on the producer.
    """

    from aptl.core.deployment._compose_stateful_model import (
        _consumer_output_names,
        _uses_per_output_mounts,
    )
    from aptl.core.deployment.realization import DeploymentStatefulConsumer

    artifact = _artifact()
    consumer = DeploymentStatefulConsumer(
        target_address="provision.node.victim",
        node_name="victim",
        service_name="victim",
        mount_destination="/run/techvault/flag-signing",
        access_mode="read_only",
        selected_outputs=("victim-signing-key",),
    )

    assert _uses_per_output_mounts(artifact, consumer) is True
    received = _consumer_output_names(artifact, consumer)
    assert received == ["victim-signing-key"]
    assert "signing-seed" not in received
