"""Exact Docker image identity across tagged and untagged digest references."""

from aptl.core.deployment._docker_image_identity import exact_inspected_image_identity


_DIGEST = "sha256:" + "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64


def test_tagged_digest_matches_dockers_canonical_repository_digest() -> None:
    requested = f"frikky/shuffle:http_1.4.0@{_DIGEST}"
    observed = f'["frikky/shuffle@{_DIGEST}"]\t{_IMAGE_ID}\tlinux/amd64\n'

    identity = exact_inspected_image_identity(observed, requested)

    assert identity is not None
    assert identity.image_id == _IMAGE_ID


def test_registry_port_and_tag_do_not_change_digest_identity() -> None:
    requested = f"localhost:5000/workers/agent:v1@{_DIGEST}"
    observed = f'["localhost:5000/workers/agent@{_DIGEST}"]\t{_IMAGE_ID}\tlinux/amd64\n'

    assert exact_inspected_image_identity(observed, requested) is not None


def test_tagged_digest_does_not_accept_other_repository_or_digest() -> None:
    requested = f"frikky/shuffle:http_1.4.0@{_DIGEST}"
    wrong_digest = f"sha256:{'c' * 64}"
    for observed_ref in (f"frikky/shuffle@{wrong_digest}", f"other/shuffle@{_DIGEST}"):
        observed = f'["{observed_ref}"]\t{_IMAGE_ID}\tlinux/amd64\n'
        assert exact_inspected_image_identity(observed, requested) is None
