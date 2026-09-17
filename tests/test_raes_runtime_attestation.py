"""Content-addressed TechVault runtime-configuration attestations."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends.raes_runtime_attestation import (
    observe_techvault_attested_concerns,
)
from aptl.validation._gate_checks import check_parse
from tests.helpers import techvault_scenario_bundle

_MISP_BACKEND_IMAGE = (
    "ghcr.io/misp/misp-docker/misp-core@"
    "sha256:0eaa4e423d5cd965b7b76aa5665e81d5c05a35bc46a4ffec2ca52e0cfe627e86"
)


class _Backend:
    def __init__(self, digest: str | None) -> None:
        self.digest = digest

    def container_image_digest(self, _container_name: str) -> str | None:
        return self.digest


def _misp_node(tmp_path: Path):
    bundle = techvault_scenario_bundle(tmp_path)
    scenario, check = check_parse(bundle.sdl_path)
    assert scenario is not None
    assert check.passed, check.diagnostics
    declared = scenario.nodes["misp"]
    return bundle, SimpleNamespace(
        name="misp",
        container_name="aptl-misp",
        runtime=declared.runtime,
        image=SimpleNamespace(image_ref=_MISP_BACKEND_IMAGE),
    )


def test_known_pack_projection_and_realized_image_are_attested(tmp_path: Path):
    bundle, node = _misp_node(tmp_path)

    concerns = observe_techvault_attested_concerns(
        _Backend(node.image.image_ref.rsplit("@", 1)[1]),
        node,
        bundle.pack_identity,
        content_verified=True,
    )

    assert CONCERN_PAYLOAD_PATH["runtime-applications"] in concerns
    assert CONCERN_PAYLOAD_PATH["runtime-platform-applications"] in concerns


def test_changed_semantic_projection_is_not_attested(tmp_path: Path):
    bundle, node = _misp_node(tmp_path)
    node.runtime.applications[0].routes[0].path = "/not-the-released-route"

    concerns = observe_techvault_attested_concerns(
        _Backend(node.image.image_ref.rsplit("@", 1)[1]),
        node,
        bundle.pack_identity,
        content_verified=True,
    )

    assert CONCERN_PAYLOAD_PATH["runtime-applications"] not in concerns


def test_wrong_realized_image_is_not_attested(tmp_path: Path):
    bundle, node = _misp_node(tmp_path)

    concerns = observe_techvault_attested_concerns(
        _Backend("sha256:" + "0" * 64),
        node,
        bundle.pack_identity,
        content_verified=True,
    )

    assert concerns == {}
