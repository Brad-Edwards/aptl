"""Exact Compose and workspace label corroboration for receipt capture."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aptl.core.deployment._compose_resource_ownership import WorkspaceOwnership

_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"


def complete_owner_labels(
    ownership: WorkspaceOwnership,
    labels: object,
    *,
    attempt_id: str,
    compose_kind: str,
    semantic_name: object,
) -> bool:
    """Require Compose identity plus every workspace and attempt owner label."""

    if not isinstance(labels, dict) or not isinstance(semantic_name, str):
        return False
    expected = ownership.labels(attempt_id=attempt_id)
    return bool(
        semantic_name
        and labels.get(_COMPOSE_PROJECT_LABEL) == ownership.project_name
        and labels.get(f"com.docker.compose.{compose_kind}") == semantic_name
        and all(labels.get(name) == value for name, value in expected.items())
    )
