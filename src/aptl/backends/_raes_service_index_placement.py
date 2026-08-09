"""Lower an ADR-088 ``service-search-index-schema`` materialization binding.

Split out of ``raes_content_realization.py`` (module-length budget). A
content-placement resource carrying a ``service_materialization`` binding is
initial *service* state (issue #889), not a node file/dataset placement: RAES
admission already validated the closed contract and computed the
``canonical_field_schema_digest`` before APTL sees the plan, so this module
only re-checks what APTL must materialize itself — portable field semantics it
can project to a native type, a resolvable target service, and a well-formed
digest — and fails closed on anything it cannot honestly realize rather than
inferring or approximating.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends._raes_content_spec import _reject
from aptl.backends.raes_service_index_schema import native_field_type as _native_field_type
from aptl.core.deployment.realization import DeploymentServiceSearchIndexSchemaRealization

_ServiceIndexResult = tuple[DeploymentServiceSearchIndexSchemaRealization | None, list[Diagnostic]]


def _validate_field_semantics(field_semantics_raw: object) -> tuple[dict[str, str] | None, str | None]:
    """Validate + normalize ``field_semantics`` into name -> semantic, or a reject reason."""

    if not isinstance(field_semantics_raw, Mapping) or not field_semantics_raw:
        return None, "service-index-schema-field-semantics-invalid"
    field_semantics: dict[str, str] = {}
    for name, semantic in field_semantics_raw.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(semantic, str)
            or _native_field_type(semantic) is None
        ):
            return None, "service-index-schema-field-semantics-invalid"
        field_semantics[name] = semantic
    return field_semantics, None


def _validate_target_and_digest(binding: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Validate ``target_service_address`` + ``canonical_field_schema_digest``, or a reject reason."""

    target_service_address = binding.get("target_service_address")
    if not isinstance(target_service_address, str) or not target_service_address:
        return None, None, "service-index-schema-target-invalid"
    digest = binding.get("canonical_field_schema_digest")
    if not isinstance(digest, str) or not digest:
        return None, None, "service-index-schema-digest-invalid"
    return target_service_address, digest, None


def resolve_service_search_index_schema(
    *,
    resource: PlannedResource,
    binding: Mapping[str, Any],
    content_name: str,
    target_address: str,
) -> _ServiceIndexResult:
    """Lower a service-search-index-schema materialization binding to a typed DTO."""

    field_semantics, reason = _validate_field_semantics(binding.get("field_semantics"))
    if reason is not None:
        return None, [_reject(resource.address, reason)]

    target_service_address, digest, reason = _validate_target_and_digest(binding)
    if reason is not None:
        return None, [_reject(resource.address, reason)]

    realization = DeploymentServiceSearchIndexSchemaRealization(
        address=resource.address,
        target_address=target_address,
        target_service_address=target_service_address,
        content_name=content_name,
        field_semantics=tuple(sorted(field_semantics.items())),
        field_schema_digest=digest,
    )
    return realization, []
