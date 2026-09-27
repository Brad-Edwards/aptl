"""Compose override persistence for admitted stateful resources."""

from __future__ import annotations

from pathlib import Path

import yaml

from aptl.core.credentials import (
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
)
from aptl.core.deployment._compose_stateful_constants import STATEFUL_OVERRIDE_RELPATH
from aptl.core.deployment._compose_stateful_model import stateful_override_payload
from aptl.core.deployment._compose_stateful_services import StatefulDumper
from aptl.core.deployment.realization import DeploymentRealizationSpec


def write_stateful_override(
    scenario_root: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> Path | None:
    """Atomically write the contained Compose stateful-resource override."""

    override_path: Path | None = None
    if realization.generated_artifacts or realization.persistent_volumes:
        payload = stateful_override_payload(scenario_root, project_name, realization)
        override_path = _canonical_generated_path(
            scenario_root,
            STATEFUL_OVERRIDE_RELPATH,
        )
        _ensure_secure_dir(override_path.parent)
        _atomic_write_secure(
            override_path,
            yaml.dump(payload, Dumper=StatefulDumper, sort_keys=True),
        )
    return override_path


__all__ = ("write_stateful_override",)
