"""Shared types for read-only runtime-materialization qualification."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeContainmentEvidence:
    """Independent boundary evidence carried by a qualified backend profile."""

    profile_id: str
    target_identity: str
    boundary_attestation_ref: str
    negative_probe_ref: str


@dataclass(frozen=True)
class RuntimeMaterializationProfile:
    """The selected backend's proven runtime-authority capability envelope."""

    name: str
    containment_evidence: RuntimeContainmentEvidence | None = None


SHARED_DOCKER_PROFILE = RuntimeMaterializationProfile(name="shared-docker")


@dataclass(frozen=True)
class RuntimeMaterializationIssue:
    """One precise unsupported-materialization diagnostic."""

    node_address: str
    field: str
    backend_profile: str
    limitation: str

    def render(self) -> str:
        """Return a bounded stable backend diagnostic."""

        return (
            "aptl.provisioner.runtime-materialization-unsupported: "
            f"node={self.node_address} field={self.field} "
            f"backend={self.backend_profile} limitation={self.limitation}"
        )


def materialization_issue(
    node_address: str,
    field: str,
    profile: RuntimeMaterializationProfile,
    limitation: str,
) -> RuntimeMaterializationIssue:
    """Build one issue against the selected backend profile."""

    return RuntimeMaterializationIssue(
        node_address=node_address,
        field=field,
        backend_profile=profile.name,
        limitation=limitation,
    )
