"""Exact-closure redistribution approval and public notice generation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aptl.appliance.inputs import CanonicalInputs
from aptl.appliance.models import ApplianceReleaseManifest


class _StrictModel(BaseModel):
    """Closed immutable base for redistribution approval records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RedistributionEntry(_StrictModel):
    """One exact distributed subject approved by the release authority."""

    kind: Literal["base-image", "oci-image", "python-wheel", "npm-lock"]
    subject: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    source_url: str = Field(min_length=1, max_length=2048)
    license_expression: str = Field(min_length=1, max_length=256)
    notice: str = Field(min_length=1, max_length=8192)

    @field_validator("source_url")
    @classmethod
    def require_https_source(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("redistribution sources must use HTTPS")
        return value


class RedistributionReview(_StrictModel):
    """Protected approval bound to one candidate's complete dependency closure."""

    schema_version: Literal["aptl.redistribution-review/v1"]
    decision: Literal["approved"]
    authority: str = Field(min_length=1, max_length=256)
    reviewed_at: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
    )
    source_commit: str = Field(pattern=r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
    canonical_inputs_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    entries: tuple[RedistributionEntry, ...]

    @model_validator(mode="after")
    def unique_entries(self) -> "RedistributionReview":
        keys = [(entry.kind, entry.subject) for entry in self.entries]
        if len(keys) != len(set(keys)):
            raise ValueError("redistribution review contains duplicate subjects")
        return self


def expected_redistribution_subjects(
    manifest: ApplianceReleaseManifest, inputs: CanonicalInputs
) -> dict[tuple[str, str], str]:
    """Derive every independently redistributed base, image, wheel, and npm lock."""

    subjects: dict[tuple[str, str], str] = {
        ("base-image", "guest-base-image"): manifest.guest.base_image_digest
    }
    for identity in sorted(set(inputs.image_roles.values())):
        subjects[("oci-image", identity)] = identity
    for asset in inputs.asset_lock.assets:
        if asset.kind == "python-wheel":
            subjects[("python-wheel", asset.source)] = "sha256:" + asset.sha256
        elif asset.kind == "project-file" and asset.source.endswith(
            "/package-lock.json"
        ):
            subjects[("npm-lock", asset.source)] = "sha256:" + asset.sha256
    return subjects


def validate_redistribution_review(
    review: RedistributionReview,
    manifest: ApplianceReleaseManifest,
    inputs: CanonicalInputs,
) -> None:
    """Fail unless the protected review covers the exact signed closure."""

    canonical = next(
        artifact
        for artifact in manifest.artifacts
        if artifact.kind == "canonical-inputs"
    )
    if (
        review.source_commit != manifest.source.source_commit
        or review.canonical_inputs_digest != canonical.sha256
    ):
        raise ValueError("redistribution review is for different release inputs")
    actual = {(entry.kind, entry.subject): entry.sha256 for entry in review.entries}
    if actual != expected_redistribution_subjects(manifest, inputs):
        raise ValueError("redistribution review does not cover the exact closure")


def render_third_party_notices(review: RedistributionReview) -> str:
    """Render the signed review as a stable public notice document."""

    lines = [
        "# Third-party redistribution notices",
        "",
        f"Approved by: {review.authority}",
        f"Reviewed at: {review.reviewed_at}",
        f"Source commit: `{review.source_commit}`",
        f"Canonical inputs: `{review.canonical_inputs_digest}`",
        "",
    ]
    for entry in sorted(review.entries, key=lambda item: (item.kind, item.subject)):
        lines.extend(
            (
                f"## {entry.kind}: {entry.subject}",
                "",
                f"- Content: `{entry.sha256}`",
                f"- Source: {entry.source_url}",
                f"- License: {entry.license_expression}",
                "",
                entry.notice,
                "",
            )
        )
    return "\n".join(lines)
