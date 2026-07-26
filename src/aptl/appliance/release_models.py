"""Preparation and launch models for appliance release envelopes."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from aptl.appliance.models import (
    _IMAGE_DIGEST_RE,
    _REQUIRED_ARTIFACT_KINDS,
    _StrictModel,
    _validate_digest,
    _validate_identifier,
    _validate_relative_path,
    ApplianceGuest,
    ArtifactKind,
    DeliveryParity,
    HostPrerequisites,
    ReleaseSource,
)


class StagedArtifact(_StrictModel):
    """One release input whose digest and size are derived during preparation."""

    artifact_id: str
    kind: ArtifactKind
    path: str

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        """Validate the stable artifact identifier."""

        return _validate_identifier(value)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """Validate the contained staged artifact path."""

        return _validate_relative_path(value)


class ParticipantTemplateBinding(_StrictModel):
    """APP-2 identity; preparation derives all content digests."""

    profile_id: str
    profile_version: int = Field(ge=1)

    @field_validator("profile_id")
    @classmethod
    def validate_profile_id(cls, value: str) -> str:
        """Validate the referenced participant profile identifier."""

        return _validate_identifier(value)


class BoundaryTemplateBinding(_StrictModel):
    """APP-1 helper identities; preparation derives the policy digest."""

    boundary_helper_image: str
    egress_proxy_image: str

    @field_validator("boundary_helper_image", "egress_proxy_image")
    @classmethod
    def validate_image_digest(cls, value: str) -> str:
        """Require an immutable helper image reference."""

        if not _IMAGE_DIGEST_RE.fullmatch(value):
            raise ValueError("release helper images must use immutable digests")
        return value


class ApplianceReleaseTemplate(_StrictModel):
    """Human-authored release metadata separated from derived identities."""

    schema_version: Literal["aptl.appliance-release-template/v1"]
    release_id: str
    source: ReleaseSource
    guest: ApplianceGuest
    artifacts: tuple[StagedArtifact, ...]
    participant: ParticipantTemplateBinding
    boundary: BoundaryTemplateBinding
    host_prerequisites: HostPrerequisites
    delivery: DeliveryParity
    upgrade_strategy: Literal["replace-golden-create-overlay"]

    @field_validator("release_id")
    @classmethod
    def validate_release_id(cls, value: str) -> str:
        """Validate the release identifier."""

        return _validate_identifier(value)

    @model_validator(mode="after")
    def validate_template(self) -> ApplianceReleaseTemplate:
        """Require one complete, unique, architecture-consistent input set."""

        ids = [artifact.artifact_id for artifact in self.artifacts]
        paths = [artifact.path for artifact in self.artifacts]
        kinds = [artifact.kind for artifact in self.artifacts]
        if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
            raise ValueError("staged artifact ids and paths must be unique")
        if set(kinds) != _REQUIRED_ARTIFACT_KINDS or len(kinds) != len(
            _REQUIRED_ARTIFACT_KINDS
        ):
            raise ValueError("template does not contain the required artifact kinds")
        if self.guest.architecture != self.host_prerequisites.architecture:
            raise ValueError("guest and host architecture must match")
        return self


class ApplianceLaunchDescriptor(_StrictModel):
    """Create-once projection that carries a verified release into first boot."""

    schema_version: Literal["aptl.appliance-launch/v1"]
    release_dir: str
    release_id: str
    aptl_version: str
    manifest_digest: str
    payload_digest: str
    golden_image_digest: str
    boundary_policy_path: str
    boundary_policy_digest: str
    boundary_helper_image: str
    egress_proxy_image: str
    participant_routes_digest: str
    host_observation_id: str

    @field_validator("release_dir", "boundary_policy_path")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        """Validate each contained descriptor path."""

        return _validate_relative_path(value)

    @field_validator(
        "manifest_digest",
        "payload_digest",
        "golden_image_digest",
        "boundary_policy_digest",
        "participant_routes_digest",
        "host_observation_id",
    )
    @classmethod
    def validate_launch_digests(cls, value: str) -> str:
        """Validate each launch-bound SHA-256 identity."""

        return _validate_digest(value)

    @field_validator("boundary_helper_image", "egress_proxy_image")
    @classmethod
    def validate_launch_images(cls, value: str) -> str:
        """Require an immutable launch helper image reference."""

        if not _IMAGE_DIGEST_RE.fullmatch(value):
            raise ValueError("launch helper images must use immutable digests")
        return value
