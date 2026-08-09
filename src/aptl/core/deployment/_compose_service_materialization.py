"""Native service materialization for Docker Compose realization.

RAES service-materialization bindings carry portable desired service state. This
module maps the admitted Cortex search-index schema binding onto Elasticsearch,
then verifies the result with a fresh native readback before Cortex starts.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from raes_contracts.canonical import canonical_json_digest

from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
    DeploymentServiceMaterializationObservation,
    DeploymentServiceMaterializationRealization,
)
from aptl.core.lab_types import LabResult

_SERVICE_MATERIALIZATION_TIMEOUT = 120
_ES_URL = "http://localhost:9200"
_SUPPORTED_FIELD_TYPES = {
    "exact-token": "keyword",
    "full-text": "text",
    "integer": "long",
    "temporal": "date",
    "boolean": "boolean",
}
_OBSERVED_FIELD_TYPES = {
    "keyword": "exact-token",
    "constant_keyword": "exact-token",
    "text": "full-text",
    "byte": "integer",
    "short": "integer",
    "integer": "integer",
    "long": "integer",
    "date": "temporal",
    "date_nanos": "temporal",
    "boolean": "boolean",
}


@dataclass(frozen=True)
class ElasticsearchSearchIndexBinding:
    """APTL-native provider binding for an admitted portable search index."""

    partition_id: str


@dataclass(frozen=True)
class ElasticsearchSearchIndexTarget:
    """Resolved native Elasticsearch index target."""

    node_address: str
    service_name: str
    container_name: str
    index_name: str


@dataclass(frozen=True)
class ElasticsearchResponse:
    """HTTP response returned by a fixed ``docker exec curl`` request."""

    status: int
    body: str


_NATIVE_SEARCH_INDEX_BINDINGS = {
    (
        "provision.content.cortex-job-index-schema",
        "provision.node.thehive-es.service.elasticsearch",
        "service-search-index-schema",
        "1",
    ): ElasticsearchSearchIndexBinding(partition_id="cortex")
}


def elasticsearch_mapping_payload(
    field_semantics: Mapping[str, str],
) -> dict[str, object]:
    """Return the Elasticsearch mapping for portable search-index semantics."""

    return {
        "mappings": {
            "properties": {
                field: {"type": _SUPPORTED_FIELD_TYPES[semantic]}
                for field, semantic in sorted(field_semantics.items())
            }
        }
    }


def portable_field_schema_digest(
    materialization: DeploymentServiceMaterializationRealization,
    field_semantics: Mapping[str, str],
) -> str:
    """Return the RAES canonical digest for a portable field schema readback."""

    return canonical_json_digest(
        {
            "interface_profile": materialization.interface_profile,
            "profile_version": materialization.profile_version,
            "projection_scope": "declared-fields",
            "field_semantics": dict(sorted(field_semantics.items())),
        }
    )


def service_materialization_error(code: str, address: str, message: str) -> str:
    """Return a bounded operator-facing service materialization error."""

    return f"Service materialization failed: [{code}] {address}: {message}"


def service_materialization_binding(
    materialization: DeploymentServiceMaterializationRealization,
) -> ElasticsearchSearchIndexBinding | None:
    """Return the native provider binding for an admitted materialization."""

    return _NATIVE_SEARCH_INDEX_BINDINGS.get(
        (
            materialization.address,
            materialization.target_service_address,
            materialization.interface_profile,
            materialization.profile_version,
        )
    )


def resolve_elasticsearch_search_index_target(
    materialization: DeploymentServiceMaterializationRealization,
    nodes: Sequence[DeploymentNodeRealization],
) -> ElasticsearchSearchIndexTarget | str:
    """Resolve the materialization's portable target to one Elasticsearch index."""

    provider = service_materialization_binding(materialization)
    if provider is None:
        return service_materialization_error(
            "aptl.service-materialization.unsupported-profile",
            materialization.address,
            "No native provider is registered for this service materialization.",
        )
    target_nodes = [
        node for node in nodes if node.address == materialization.target_address
    ]
    if len(target_nodes) != 1:
        return service_materialization_error(
            "aptl.service-materialization.target-unavailable",
            materialization.address,
            "The declared target node did not resolve to exactly one backend node.",
        )
    node = target_nodes[0]
    if not node.service_name or not node.container_name:
        return service_materialization_error(
            "aptl.service-materialization.target-unavailable",
            materialization.address,
            "The declared target node has no backend service/container binding.",
        )
    index_name = _resolve_search_index_name(node, provider.partition_id)
    if index_name is None:
        return service_materialization_error(
            "aptl.service-materialization.binding-unresolved",
            materialization.address,
            "The declared Elasticsearch partition did not resolve to one index.",
        )
    return ElasticsearchSearchIndexTarget(
        node_address=node.address,
        service_name=node.service_name,
        container_name=node.container_name,
        index_name=index_name,
    )


def service_materialization_field_semantics(
    materialization: DeploymentServiceMaterializationRealization,
) -> dict[str, str] | str:
    """Return the portable field semantics carried by the RAES binding."""

    raw = materialization.binding.get("field_semantics")
    if not isinstance(raw, Mapping) or not raw:
        return service_materialization_error(
            "aptl.service-materialization.binding-unresolved",
            materialization.address,
            "The service materialization does not carry a portable field schema.",
        )
    field_semantics: dict[str, str] = {}
    for field, semantic in raw.items():
        if (
            not isinstance(field, str)
            or not isinstance(semantic, str)
            or semantic not in _SUPPORTED_FIELD_TYPES
        ):
            return service_materialization_error(
                "aptl.service-materialization.binding-unresolved",
                materialization.address,
                "The service materialization carries an unsupported field semantic.",
            )
        field_semantics[field] = semantic
    expected = materialization.binding.get("canonical_field_schema_digest")
    observed = portable_field_schema_digest(materialization, field_semantics)
    if expected != observed:
        return service_materialization_error(
            "aptl.service-materialization.binding-unresolved",
            materialization.address,
            "The portable field schema digest does not match the carried schema.",
        )
    return field_semantics


def readback_field_semantics(
    materialization: DeploymentServiceMaterializationRealization,
    index_name: str,
    mapping_payload: Mapping[str, object],
) -> dict[str, str] | str:
    """Project Elasticsearch mapping readback to portable field semantics."""

    expected = service_materialization_field_semantics(materialization)
    if isinstance(expected, str):
        return expected
    properties = _mapping_properties(mapping_payload, index_name)
    if properties is None:
        return service_materialization_error(
            "aptl.service-materialization.readback-mismatch",
            materialization.address,
            "Elasticsearch did not return the declared index mapping.",
        )
    observed: dict[str, str] = {}
    for field in expected:
        raw_field = properties.get(field)
        if not isinstance(raw_field, Mapping):
            return service_materialization_error(
                "aptl.service-materialization.readback-mismatch",
                materialization.address,
                "Elasticsearch mapping is missing a declared field.",
            )
        field_type = raw_field.get("type")
        semantic = _OBSERVED_FIELD_TYPES.get(field_type)
        if semantic is None:
            return service_materialization_error(
                "aptl.service-materialization.readback-mismatch",
                materialization.address,
                "Elasticsearch mapping reports an unsupported field type.",
            )
        observed[field] = semantic
    digest = portable_field_schema_digest(materialization, observed)
    if digest != materialization.binding.get("canonical_field_schema_digest"):
        return service_materialization_error(
            "aptl.service-materialization.readback-mismatch",
            materialization.address,
            "Elasticsearch mapping readback does not match the portable schema.",
        )
    return observed


class ComposeServiceMaterializationMixin:
    """Apply and observe native service-materialization bindings."""

    def _realize_service_materializations(
        self,
        realization: DeploymentRealizationSpec,
        profiles: list[str],
        *,
        build: bool,
        compose_files: Sequence[Path] | None,
        scenario_root: Path,
    ) -> LabResult | None:
        if not realization.service_materializations:
            return None
        targets = [
            resolve_elasticsearch_search_index_target(item, realization.nodes)
            for item in realization.service_materializations
        ]
        errors = [item for item in targets if isinstance(item, str)]
        if errors:
            return LabResult(success=False, error=errors[0])
        target_nodes = _unique_target_nodes(
            realization,
            [item for item in targets if isinstance(item, ElasticsearchSearchIndexTarget)],
        )
        start_result = self._start_service_materialization_targets(
            profiles,
            target_nodes,
            build=build,
            compose_files=compose_files,
            scenario_root=scenario_root,
        )
        if start_result is not None:
            return start_result
        health_failures = self._await_realized_service_health(
            replace(realization, nodes=tuple(target_nodes))
        )
        if health_failures:
            return LabResult(success=False, error="; ".join(health_failures[:5]))
        for materialization, target in zip(
            realization.service_materializations,
            targets,
            strict=True,
        ):
            assert isinstance(target, ElasticsearchSearchIndexTarget)
            error = self._reconcile_elasticsearch_search_index_schema(
                materialization,
                target,
            )
            if error is not None:
                return LabResult(success=False, error=error)
        return None

    def _start_service_materialization_targets(
        self,
        profiles: list[str],
        nodes: Sequence[DeploymentNodeRealization],
        *,
        build: bool,
        compose_files: Sequence[Path] | None,
        scenario_root: Path,
    ) -> LabResult | None:
        services = sorted({node.service_name for node in nodes if node.service_name})
        if not services:
            return LabResult(
                success=False,
                error=service_materialization_error(
                    "aptl.service-materialization.target-unavailable",
                    "service-materialization",
                    "No backend service resolved for native materialization.",
                ),
            )
        cmd = self._build_command(
            "up", profiles, compose_files=compose_files, scenario_root=scenario_root
        )
        if build and not getattr(self, "_offline_staged", False):
            cmd.append("--build")
        if getattr(self, "_offline_staged", False):
            cmd.extend(["--pull", "never"])
        cmd.append("-d")
        cmd.extend(services)
        result = self._run(cmd)
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=service_materialization_error(
                    "aptl.service-materialization.target-unavailable",
                    "service-materialization",
                    "The native service target did not start.",
                ),
            )
        return None

    def _reconcile_elasticsearch_search_index_schema(
        self,
        materialization: DeploymentServiceMaterializationRealization,
        target: ElasticsearchSearchIndexTarget,
    ) -> str | None:
        field_semantics = service_materialization_field_semantics(materialization)
        if isinstance(field_semantics, str):
            return field_semantics
        exists = self._elasticsearch_request(target.container_name, "GET", target.index_name)
        if isinstance(exists, str):
            return exists
        if exists.status == 404:
            create = self._elasticsearch_request(
                target.container_name,
                "PUT",
                target.index_name,
                payload=elasticsearch_mapping_payload(field_semantics),
            )
            if isinstance(create, str):
                return create
            if create.status not in {200, 201}:
                return service_materialization_error(
                    "aptl.service-materialization.native-request-failed",
                    materialization.address,
                    "Elasticsearch rejected index creation.",
                )
        elif exists.status != 200:
            return service_materialization_error(
                "aptl.service-materialization.native-request-failed",
                materialization.address,
                "Elasticsearch did not return index state.",
            )
        return self._verify_elasticsearch_search_index_schema(materialization, target)

    def _verify_elasticsearch_search_index_schema(
        self,
        materialization: DeploymentServiceMaterializationRealization,
        target: ElasticsearchSearchIndexTarget,
    ) -> str | None:
        readback = self._elasticsearch_request(
            target.container_name, "GET", f"{target.index_name}/_mapping"
        )
        if isinstance(readback, str):
            return readback
        if readback.status != 200:
            return service_materialization_error(
                "aptl.service-materialization.native-request-failed",
                materialization.address,
                "Elasticsearch did not return mapping readback.",
            )
        mapping = _json_object(readback.body)
        if mapping is None:
            return service_materialization_error(
                "aptl.service-materialization.native-request-failed",
                materialization.address,
                "Elasticsearch mapping readback was not a JSON object.",
            )
        semantics = readback_field_semantics(materialization, target.index_name, mapping)
        if isinstance(semantics, str):
            return semantics
        return None

    def observe_service_materialization(
        self,
        materialization: DeploymentServiceMaterializationRealization,
        nodes: Sequence[DeploymentNodeRealization],
    ) -> DeploymentServiceMaterializationObservation:
        target = resolve_elasticsearch_search_index_target(materialization, nodes)
        if isinstance(target, str):
            return DeploymentServiceMaterializationObservation(
                realized=False,
                evidence={"error": target},
            )
        error = self._verify_elasticsearch_search_index_schema(materialization, target)
        if error is not None:
            return DeploymentServiceMaterializationObservation(
                realized=False,
                evidence={"error": error},
            )
        return DeploymentServiceMaterializationObservation(
            realized=True,
            binding=dict(materialization.binding),
            evidence={
                "mechanism": "elasticsearch-mapping-readback",
                "target_node": target.node_address,
                "target_service": target.service_name,
            },
        )

    def _elasticsearch_request(
        self,
        container_name: str,
        method: str,
        path: str,
        *,
        payload: Mapping[str, object] | None = None,
    ) -> ElasticsearchResponse | str:
        url = f"{_ES_URL}/{path.lstrip('/')}"
        cmd = [
            "docker",
            "exec",
            *(["-i"] if payload is not None else []),
            container_name,
            "curl",
            "-sS",
            "-X",
            method,
            "-H",
            "Content-Type: application/json",
            "-w",
            "\n%{http_code}",
            url,
        ]
        if payload is None:
            result = self._run(cmd, timeout=_SERVICE_MATERIALIZATION_TIMEOUT)
        else:
            cmd.extend(["--data-binary", "@-"])
            result = self._run_with_input(
                cmd,
                json.dumps(payload, sort_keys=True),
                timeout=_SERVICE_MATERIALIZATION_TIMEOUT,
            )
        if result.returncode != 0:
            return service_materialization_error(
                "aptl.service-materialization.native-request-failed",
                "service-materialization",
                "Native Elasticsearch request failed.",
            )
        return _parse_elasticsearch_response(result.stdout)


def _unique_target_nodes(
    realization: DeploymentRealizationSpec,
    targets: Sequence[ElasticsearchSearchIndexTarget],
) -> tuple[DeploymentNodeRealization, ...]:
    addresses = {target.node_address for target in targets}
    return tuple(node for node in realization.nodes if node.address in addresses)


def _resolve_search_index_name(
    node: DeploymentNodeRealization,
    partition_id: str,
) -> str | None:
    runtime = node.runtime
    stores = getattr(runtime, "datastore_services", ()) if runtime else ()
    matches: list[str] = []
    for store in stores:
        if _enum_value(getattr(store, "engine", "")) != "elasticsearch":
            continue
        if _enum_value(getattr(store, "data_model", "")) != "search_index":
            continue
        partitions = getattr(store, "partitions", ())
        partition_names = [
            getattr(partition, "name", "")
            for partition in partitions
            if getattr(partition, "partition_id", "") == partition_id
        ]
        mapping_names = {
            getattr(mapping, "name", "")
            for mapping in getattr(store, "mappings", ())
            if getattr(mapping, "partition_ref", "") == partition_id
        }
        matches.extend(
            name
            for name in partition_names
            if name and (not mapping_names or name in mapping_names)
        )
    unique = sorted(set(matches))
    return unique[0] if len(unique) == 1 else None


def _mapping_properties(
    payload: Mapping[str, object],
    index_name: str,
) -> Mapping[str, object] | None:
    wrapper = payload.get(index_name)
    if isinstance(wrapper, Mapping):
        payload = wrapper
    mappings = payload.get("mappings")
    if not isinstance(mappings, Mapping):
        return None
    properties = mappings.get("properties")
    return properties if isinstance(properties, Mapping) else None


def _json_object(raw: str) -> Mapping[str, object] | None:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _parse_elasticsearch_response(stdout: str) -> ElasticsearchResponse | str:
    body, separator, status_text = stdout.rpartition("\n")
    if not separator or not status_text.isdigit():
        return service_materialization_error(
            "aptl.service-materialization.native-request-failed",
            "service-materialization",
            "Native Elasticsearch response did not include an HTTP status.",
        )
    return ElasticsearchResponse(status=int(status_text), body=body)


def _enum_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return raw if isinstance(raw, str) else ""
