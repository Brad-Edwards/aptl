"""Lower a declared evidence dataset into its run-store carrier (#875).

Split out of :mod:`aptl.backends.raes_content_realization`: a ``dataset``
placement is the one content type that materializes nothing onto a node, so it
takes a different lowering path from the file/directory/pack shapes and carries
its own validation. A dataset that declares any materialization field, a
malformed item list, or a malformed tag list fails closed here rather than
reaching the run store.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends._raes_content_spec import _is_sensitive, _reject
from aptl.backends.raes_realization_model import ParticipantDatasetRealization


def _resolve_dataset_content(
    *,
    resource: PlannedResource,
    spec: Mapping[str, Any],
    content_name: str,
    target_address: str,
) -> tuple[ParticipantDatasetRealization | None, list[Diagnostic]]:
    """Lower one empty logical evidence dataset into the run-store carrier."""

    dataset: ParticipantDatasetRealization | None = None
    diagnostics: list[Diagnostic] = []
    forbidden_values = (
        spec.get("source"),
        spec.get("text"),
        spec.get("path"),
        spec.get("destination"),
    )
    if any(value not in (None, "") for value in forbidden_values):
        diagnostics = [_reject(resource.address, "dataset-carries-materialization")]
    else:
        item_names = _dataset_item_names(spec.get("items"))
        tags = _dataset_tags(spec.get("tags", []))
        if item_names is None:
            diagnostics = [_reject(resource.address, "dataset-items-invalid")]
        elif tags is None:
            diagnostics = [_reject(resource.address, "dataset-tags-invalid")]
        else:
            dataset = ParticipantDatasetRealization(
                address=resource.address,
                target_address=target_address,
                content_name=content_name,
                item_names=item_names,
                tags=tags,
                sensitive=_is_sensitive(spec),
            )
    return dataset, diagnostics


def _dataset_item_names(raw_items: object) -> tuple[str, ...] | None:
    """Validate and normalize the declared dataset item names."""

    if not isinstance(raw_items, list) or not raw_items:
        return None
    item_names: list[str] = []
    for item in raw_items:
        name = item.get("name") if isinstance(item, Mapping) else None
        if not isinstance(name, str) or not name or name in item_names:
            return None
        item_names.append(name)
    return tuple(item_names)


def _dataset_tags(raw_tags: object) -> tuple[str, ...] | None:
    """Validate and normalize the declared dataset tags."""

    if not isinstance(raw_tags, list) or any(
        not isinstance(tag, str) or not tag for tag in raw_tags
    ):
        return None
    return tuple(raw_tags)
