"""Fail-closed redistribution review coverage for public appliance bytes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aptl.appliance.redistribution import (
    RedistributionEntry,
    RedistributionReview,
    render_third_party_notices,
    validate_redistribution_review,
)


def _fixtures():
    canonical_digest = "sha256:" + "a" * 64
    image_digest = "sha256:" + "b" * 64
    wheel_digest = "c" * 64
    lock_digest = "d" * 64
    manifest = SimpleNamespace(
        source=SimpleNamespace(source_commit="1" * 40),
        guest=SimpleNamespace(base_image_digest="sha256:" + "e" * 64),
        artifacts=(SimpleNamespace(kind="canonical-inputs", sha256=canonical_digest),),
    )
    inputs = SimpleNamespace(
        image_roles={"scenario.one": image_digest, "scenario.two": image_digest},
        asset_lock=SimpleNamespace(
            assets=(
                SimpleNamespace(
                    kind="python-wheel",
                    source="wheelhouse/example-1.0-py3-none-any.whl",
                    sha256=wheel_digest,
                ),
                SimpleNamespace(
                    kind="project-file",
                    source="project/web/package-lock.json",
                    sha256=lock_digest,
                ),
            )
        ),
    )
    subjects = (
        ("base-image", "guest-base-image", "sha256:" + "e" * 64),
        ("oci-image", image_digest, image_digest),
        (
            "python-wheel",
            "wheelhouse/example-1.0-py3-none-any.whl",
            "sha256:" + wheel_digest,
        ),
        (
            "npm-lock",
            "project/web/package-lock.json",
            "sha256:" + lock_digest,
        ),
    )
    entries = tuple(
        RedistributionEntry(
            kind=kind,
            subject=subject,
            sha256=digest,
            source_url="https://example.invalid/source",
            license_expression="MIT",
            notice="License and copyright notice retained.",
        )
        for kind, subject, digest in subjects
    )
    review = RedistributionReview(
        schema_version="aptl.redistribution-review/v1",
        decision="approved",
        authority="release compliance",
        reviewed_at="2026-09-18T00:00:00Z",
        source_commit="1" * 40,
        canonical_inputs_digest=canonical_digest,
        entries=entries,
    )
    return manifest, inputs, review


def test_review_covers_each_exact_distributed_subject_and_renders_notices() -> None:
    manifest, inputs, review = _fixtures()

    validate_redistribution_review(review, manifest, inputs)
    notices = render_third_party_notices(review)

    assert "Third-party redistribution notices" in notices
    assert "project/web/package-lock.json" in notices
    assert "sha256:" + "b" * 64 in notices


def test_review_rejects_missing_or_different_candidate_subject() -> None:
    manifest, inputs, review = _fixtures()

    with pytest.raises(ValueError, match="exact closure"):
        validate_redistribution_review(
            review.model_copy(update={"entries": review.entries[:-1]}),
            manifest,
            inputs,
        )

    with pytest.raises(ValueError, match="different release inputs"):
        validate_redistribution_review(
            review.model_copy(update={"canonical_inputs_digest": "sha256:" + "f" * 64}),
            manifest,
            inputs,
        )
