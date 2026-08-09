"""Docker Compose native service-materialization tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from raes.runtime_configuration import RuntimeConfiguration
from raes.runtime_datastore import (
    RuntimeDatastoreDataModel,
    RuntimeDatastoreEngine,
    RuntimeDatastoreMapping,
    RuntimeDatastorePartition,
    RuntimeDatastoreService,
)
from raes_contracts.canonical import canonical_json_digest

from aptl.core.deployment._compose_service_materialization import (
    ComposeServiceMaterializationMixin,
    elasticsearch_mapping_payload,
    readback_field_semantics,
    resolve_elasticsearch_search_index_target,
)
from aptl.core.deployment.realization import (
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
    DeploymentServiceMaterializationRealization,
)


def _field_schema_digest(field_semantics: dict[str, str]) -> str:
    return canonical_json_digest(
        {
            "interface_profile": "service-search-index-schema",
            "profile_version": "1",
            "projection_scope": "declared-fields",
            "field_semantics": field_semantics,
        }
    )


def _materialization() -> DeploymentServiceMaterializationRealization:
    field_semantics = {
        "key": "exact-token",
        "relations": "exact-token",
        "status": "exact-token",
    }
    return DeploymentServiceMaterializationRealization(
        address="provision.content.cortex-job-index-schema",
        target_address="provision.node.thehive-es",
        binding={
            "canonical_content_digest": (
                "sha256:dcb95473071eba666890cefef3c6dab8c35de373a28e268c0b474c83f6e12152"
            ),
            "canonical_field_schema_digest": _field_schema_digest(field_semantics),
            "field_semantics": field_semantics,
            "interface_profile": "service-search-index-schema",
            "profile_version": "1",
            "target_service_address": "provision.node.thehive-es.service.elasticsearch",
        },
    )


def _thehive_es_node() -> DeploymentNodeRealization:
    return DeploymentNodeRealization(
        address="provision.node.thehive-es",
        name="thehive-es",
        service_name="thehive-es",
        container_name="aptl-thehive-es",
        networks=("aptl-security",),
        runtime=RuntimeConfiguration(
            datastore_services=[
                RuntimeDatastoreService(
                    datastore_service_id="elasticsearch",
                    service="elasticsearch",
                    engine=RuntimeDatastoreEngine.ELASTICSEARCH,
                    data_model=RuntimeDatastoreDataModel.SEARCH_INDEX,
                    partitions=[
                        RuntimeDatastorePartition(
                            partition_id="cortex",
                            kind="index",
                            name="cortex_6",
                            shard_count=5,
                            replica_count=0,
                        )
                    ],
                    mappings=[
                        RuntimeDatastoreMapping(
                            mapping_id="cortex-jobs",
                            name="cortex_6",
                            partition_ref="cortex",
                            top_level_field_count=3,
                        )
                    ],
                )
            ]
        ),
    )


def _mapping_body(field_type: str = "keyword") -> str:
    return json.dumps(
        {
            "cortex_6": {
                "mappings": {
                    "properties": {
                        "key": {"type": field_type},
                        "relations": {"type": "keyword"},
                        "status": {"type": "keyword"},
                    }
                }
            }
        }
    )


def test_search_index_schema_projects_to_elasticsearch_keyword_fields():
    payload = elasticsearch_mapping_payload(
        {
            "key": "exact-token",
            "relations": "exact-token",
            "status": "exact-token",
        }
    )

    assert payload == {
        "mappings": {
            "properties": {
                "key": {"type": "keyword"},
                "relations": {"type": "keyword"},
                "status": {"type": "keyword"},
            }
        }
    }


def test_search_index_target_resolves_from_runtime_datastore_inventory():
    target = resolve_elasticsearch_search_index_target(
        _materialization(), [_thehive_es_node()]
    )

    assert not isinstance(target, str)
    assert target.service_name == "thehive-es"
    assert target.container_name == "aptl-thehive-es"
    assert target.index_name == "cortex_6"


def test_mapping_readback_matches_compiled_portable_digest():
    semantics = readback_field_semantics(
        _materialization(),
        "cortex_6",
        json.loads(_mapping_body()),
    )

    assert semantics == {
        "key": "exact-token",
        "relations": "exact-token",
        "status": "exact-token",
    }


def test_mapping_readback_rejects_dynamic_text_mapping():
    error = readback_field_semantics(
        _materialization(),
        "cortex_6",
        json.loads(_mapping_body(field_type="text")),
    )

    assert isinstance(error, str)
    assert "aptl.service-materialization.readback-mismatch" in error


class _Backend(ComposeServiceMaterializationMixin):
    _offline_staged = False

    def __init__(self, responses: list[subprocess.CompletedProcess[str]]) -> None:
        self.responses = responses
        self.commands: list[list[str]] = []
        self.inputs: list[str] = []

    def _build_command(
        self,
        action: str,
        profiles: list[str],
        *,
        compose_files: object = None,
        scenario_root: Path | None = None,
    ) -> list[str]:
        return ["docker", "compose", *[f"--profile={profile}" for profile in profiles], action]

    def _run(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(cmd)
        return self.responses.pop(0)

    def _run_with_input(
        self,
        cmd: list[str],
        payload: str,
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(cmd)
        self.inputs.append(payload)
        return self.responses.pop(0)

    def _await_realized_service_health(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        return []


def _completed(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def _spec() -> DeploymentRealizationSpec:
    return DeploymentRealizationSpec(
        profiles=("soc",),
        nodes=(_thehive_es_node(),),
        networks=(DeploymentNetworkRealization("aptl-security"),),
        service_materializations=(_materialization(),),
    )


def test_realization_starts_target_then_creates_missing_index_and_reads_back():
    backend = _Backend(
        [
            _completed(),
            _completed('{"error":"missing"}\n404'),
            _completed('{"acknowledged":true}\n200'),
            _completed(f"{_mapping_body()}\n200"),
        ]
    )

    result = backend._realize_service_materializations(
        _spec(),
        ["soc"],
        build=True,
        compose_files=None,
        scenario_root=Path("."),
    )

    assert result is None
    assert backend.commands[0][-2:] == ["-d", "thehive-es"]
    assert all("-X DELETE" not in " ".join(command) for command in backend.commands)
    assert backend.inputs == [
        json.dumps(
            {
                "mappings": {
                    "properties": {
                        "key": {"type": "keyword"},
                        "relations": {"type": "keyword"},
                        "status": {"type": "keyword"},
                    }
                }
            },
            sort_keys=True,
        )
    ]


def test_observation_reads_mapping_without_mutating_elasticsearch():
    backend = _Backend([_completed(f"{_mapping_body()}\n200")])

    observed = backend.observe_service_materialization(
        _materialization(), [_thehive_es_node()]
    )

    assert observed.realized is True
    assert observed.binding == _materialization().binding
    assert len(backend.commands) == 1
    assert backend.inputs == []
    assert backend.commands[0][2:7] == [
        "aptl-thehive-es",
        "curl",
        "-sS",
        "-X",
        "GET",
    ]
