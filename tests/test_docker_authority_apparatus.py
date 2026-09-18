"""Issue #912: the apparatus that mediates an admitted Docker authority.

The proxy's own policy is covered in `test_docker_authority_proxy.py`. These
tests cover the wiring that decides the proxy is there at all, what it is told
to permit, and what the declaring workload is actually handed.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from aptl.core.deployment._compose_docker_authority import (
    AUTHORITY_COMPOSE_FILE,
    AUTHORITY_SERVICE,
    admitted_authority_images,
    authority_compose_file,
    authority_declaration_error,
    authority_requested,
    authority_socket_path,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.runtime_authority import (
    DeploymentDockerAuthorityAdmission,
    DeploymentSpawnImageRequirement,
    is_mediated_authority_socket,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_WORKER = "ghcr.io/shuffle/shuffle-worker@sha256:" + "a" * 64
_APP = "frikky/shuffle@sha256:" + "b" * 64


def _requirement(image: str, template: str) -> DeploymentSpawnImageRequirement:
    return DeploymentSpawnImageRequirement(
        node_address="provision.node.shuffle-orborus",
        authority_id="shuffle-orborus",
        template_id=template,
        image_ref=image,
        execution_timeout_seconds=600,
        child_label="",
        expected_count=0,
    )


def _spec(images: tuple[str, ...] = (_WORKER, _APP)) -> DeploymentRealizationSpec:
    admission = DeploymentDockerAuthorityAdmission(
        node_address="provision.node.shuffle-orborus",
        service_name="shuffle-orborus",
        engine="docker",
        privilege_class="host_root_equivalent",
        endpoint_kind="unix_socket",
        endpoint_source="/var/run/docker.sock",
        endpoint_target="/var/run/docker.sock",
        endpoint_read_write=True,
        spawn_requirements=tuple(
            _requirement(image, f"t{index}") for index, image in enumerate(images)
        ),
    )
    return DeploymentRealizationSpec(
        profiles=("soc",),
        nodes=(),
        networks=(),
        docker_authority_admissions=(admission,),
    )


def test_an_admitted_authority_always_requests_its_mediation():
    assert authority_requested(_spec()) is True
    assert authority_requested(replace(_spec(), docker_authority_admissions=())) is False


def test_the_permitted_images_are_exactly_the_admitted_ones():
    """The boundary is told what the pack declared, and nothing else."""

    assert admitted_authority_images(_spec()) == tuple(sorted((_WORKER, _APP)))


def test_an_authority_with_no_admitted_image_permits_none():
    """A declaration that names no image has not authorized one."""

    spec = _spec()
    admission = replace(spec.docker_authority_admissions[0], spawn_requirements=())
    spec = replace(spec, docker_authority_admissions=(admission,))

    assert admitted_authority_images(spec) == ()


def test_the_rendered_apparatus_carries_the_admitted_policy(tmp_path):
    path = authority_compose_file(PROJECT_ROOT, _spec(), tmp_path)
    model = yaml.safe_load(path.read_text(encoding="utf-8"))
    service = model["services"][AUTHORITY_SERVICE]

    permitted = service["environment"]["APTL_DOCKER_AUTHORITY_IMAGES"].splitlines()
    assert sorted(permitted) == sorted((_WORKER, _APP))

    sources = {mount["source"]: mount for mount in service["volumes"]}
    # The apparatus holds the host socket; that is the whole point of it.
    assert "/var/run/docker.sock" in sources
    # And it owns the directory the mediated socket is created in.
    assert str(authority_socket_path(tmp_path).parent) in sources
    assert authority_socket_path(tmp_path).parent.is_dir()

    # It joins no scenario network, so an in-world workload cannot reach it
    # other than through the socket it is meant to use.
    assert service["network_mode"] == "none"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    # The declaring workload bind-mounts the socket as a file, so the apparatus
    # must report healthy -- meaning the socket exists and answers -- first.
    assert service["healthcheck"]["test"][0] == "CMD-SHELL"


def test_the_rendered_apparatus_never_leaves_a_placeholder_source(tmp_path):
    path = authority_compose_file(PROJECT_ROOT, _spec(), tmp_path)
    model = yaml.safe_load(path.read_text(encoding="utf-8"))

    rendered = yaml.safe_dump(model)
    assert "generated:" not in rendered


def test_a_pack_that_owns_the_apparatus_name_is_refused():
    """The apparatus must not silently lose to a scenario service of its name."""

    spec = _spec()
    admission = replace(spec.docker_authority_admissions[0], service_name=AUTHORITY_SERVICE)
    spec = replace(spec, docker_authority_admissions=(admission,))

    assert authority_declaration_error(spec) == "aptl.docker-authority.ownership-conflict"


def test_no_authority_needs_no_apparatus():
    assert authority_declaration_error(replace(_spec(), docker_authority_admissions=())) is None


def test_the_shipped_apparatus_model_never_hands_over_the_host_socket():
    """Read the committed file: the holder's grant must not be the host's own."""

    model = yaml.safe_load(
        (PROJECT_ROOT / AUTHORITY_COMPOSE_FILE).read_text(encoding="utf-8")
    )
    service = model["services"][AUTHORITY_SERVICE]
    targets = {mount["target"] for mount in service["volumes"]}

    # The apparatus reaches the daemon; nothing else in the model does.
    assert "/var/run/docker.sock" in targets
    assert service["build"]["dockerfile"] == (
        "containers/docker-authority-proxy/Dockerfile"
    )


@pytest.mark.parametrize(
    ("source", "allowed"),
    [
        ("/srv/.aptl/realization/docker-authority/docker.sock", True),
        ("/var/run/docker.sock", False),
        ("/var/run", False),
        ("/", False),
    ],
)
def test_only_a_mediated_source_is_a_canonical_grant(source, allowed):
    """One definition, shared by the compose model, readback and excess gate."""

    assert (
        is_mediated_authority_socket(
            source=source, target="/var/run/docker.sock", read_write=True
        )
        is allowed
    )
