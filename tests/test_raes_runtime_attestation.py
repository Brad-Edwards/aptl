"""Content-addressed TechVault runtime-configuration attestations."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends.raes_runtime_attestation import (
    observe_techvault_attested_concerns,
)
from aptl.core.deployment._compose_stateful_readiness import declared_wazuh_fact_ids
from aptl.validation._gate_checks import check_parse
from tests.helpers import techvault_scenario_bundle

_MISP_BACKEND_IMAGE = (
    "ghcr.io/misp/misp-docker/misp-core@"
    "sha256:0eaa4e423d5cd965b7b76aa5665e81d5c05a35bc46a4ffec2ca52e0cfe627e86"
)


class _Backend:
    def __init__(
        self,
        digest: str | None,
        declared_wazuh_attestation: dict[str, object] | None = None,
    ) -> None:
        self.digest = digest
        self.declared_wazuh_attestation = declared_wazuh_attestation or {}

    def container_image_digest(self, _container_name: str) -> str | None:
        return self.digest


def _matched(*fact_ids: str) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "fact_id": fact_id,
            "expected": "declared",
            "observed": "declared",
            "status": "matched",
            "failure_category": "",
        }
        for fact_id in fact_ids
    )


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


def _wazuh_node(tmp_path: Path, name: str, service_name: str):
    bundle = techvault_scenario_bundle(tmp_path)
    scenario, check = check_parse(bundle.sdl_path)
    assert scenario is not None
    assert check.passed, check.diagnostics
    declared = scenario.nodes[name]
    return bundle, SimpleNamespace(
        name=name,
        backend_services=(service_name,),
        container_name=f"aptl-{name}",
        runtime=declared.runtime,
        image=None,
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


def test_wazuh_runtime_facts_require_native_declared_fact_attestation(tmp_path: Path):
    bundle, node = _wazuh_node(tmp_path, "wazuh-indexer", "wazuh.indexer")
    path = CONCERN_PAYLOAD_PATH["runtime-datastore-services"]

    absent = observe_techvault_attested_concerns(
        _Backend(None), node, bundle.pack_identity, content_verified=True
    )
    observed = observe_techvault_attested_concerns(
        _Backend(
            None,
            {"wazuh.indexer": _matched(*declared_wazuh_fact_ids(node))},
        ),
        node,
        bundle.pack_identity,
        content_verified=True,
    )

    assert path not in absent
    assert path in observed


def test_wazuh_runtime_facts_require_the_exact_declared_observation_set(tmp_path: Path):
    bundle, node = _wazuh_node(tmp_path, "wazuh-indexer", "wazuh.indexer")
    required = sorted(declared_wazuh_fact_ids(node))
    assert len(required) > 1

    concerns = observe_techvault_attested_concerns(
        _Backend(None, {"wazuh.indexer": _matched(*required[:-1])}),
        node,
        bundle.pack_identity,
        content_verified=True,
    )

    assert CONCERN_PAYLOAD_PATH["runtime-datastore-services"] not in concerns


def test_non_wazuh_datastore_does_not_require_wazuh_attestation(tmp_path: Path):
    bundle = techvault_scenario_bundle(tmp_path)
    scenario, check = check_parse(bundle.sdl_path)
    assert scenario is not None
    assert check.passed, check.diagnostics
    declared = scenario.nodes["misp-redis"]
    node = SimpleNamespace(
        name="misp-redis",
        backend_services=("misp.redis",),
        container_name="aptl-misp-redis",
        runtime=declared.runtime,
        image=None,
    )

    concerns = observe_techvault_attested_concerns(
        _Backend(None), node, bundle.pack_identity, content_verified=True
    )

    assert CONCERN_PAYLOAD_PATH["runtime-datastore-services"] in concerns
