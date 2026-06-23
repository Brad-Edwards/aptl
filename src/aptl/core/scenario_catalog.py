"""Curated ACES startup scenario catalog resolution."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic import model_validator

from aptl.utils.redaction import redact

CATALOG_RELATIVE_PATH = Path("scenarios") / "catalog.json"
_SCENARIO_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class ScenarioCatalogEntry(BaseModel):
    """One operator-facing scenario alias in the curated catalog."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    path: str
    description: str = ""

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _SCENARIO_ID.match(value):
            raise ValueError(
                "scenario id must start with a lowercase alphanumeric "
                "character and contain only lowercase letters, digits, dots, "
                "underscores, and hyphens"
            )
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scenario path must not be empty")
        return value


class ScenarioCatalog(BaseModel):
    """Strict schema for the repo-owned curated scenario catalog."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1)
    scenarios: list[ScenarioCatalogEntry] = Field(default_factory=list)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("scenario catalog version must be 1")
        return value

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "ScenarioCatalog":
        ids = [entry.id for entry in self.scenarios]
        duplicates = sorted(
            {scenario_id for scenario_id in ids if ids.count(scenario_id) > 1}
        )
        if duplicates:
            raise ValueError(f"duplicate scenario id(s): {', '.join(duplicates)}")
        return self

    def get(self, scenario_id: str) -> ScenarioCatalogEntry | None:
        """Return the catalog entry for ``scenario_id``, if present."""
        for entry in self.scenarios:
            if entry.id == scenario_id:
                return entry
        return None


def load_scenario_catalog(project_dir: Path) -> ScenarioCatalog:
    """Load the curated ACES startup scenario catalog for ``project_dir``."""
    catalog_path = project_dir / CATALOG_RELATIVE_PATH
    if not catalog_path.is_file():
        raise ValueError(f"Scenario catalog does not exist: {catalog_path}")
    try:
        raw = yaml.safe_load(catalog_path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Invalid scenario catalog data: {catalog_path}: {exc}"
        ) from exc
    if not isinstance(raw, dict):
        raise ValueError(f"Scenario catalog root must be a mapping: {catalog_path}")
    try:
        return ScenarioCatalog.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"Invalid scenario catalog: {catalog_path}: {exc}") from exc


def resolve_scenario_selection(
    project_dir: Path,
    *,
    scenario_id: str | None = None,
    scenario_path: Path | None = None,
) -> Path | None:
    """Resolve an optional catalog id or explicit path into an ACES SDL file."""
    if scenario_id and scenario_path is not None:
        raise ValueError("scenario selectors are mutually exclusive")
    if not scenario_id and scenario_path is None:
        return None
    if scenario_id:
        catalog = load_scenario_catalog(project_dir)
        entry = catalog.get(scenario_id)
        if entry is None:
            available = ", ".join(entry.id for entry in catalog.scenarios) or "none"
            raise ValueError(
                f"Unknown scenario id '{scenario_id}'. Available scenarios: {available}"
            )
        selected = Path(entry.path)
    else:
        assert scenario_path is not None
        selected = scenario_path
    resolved = _resolve_project_file(project_dir, selected)
    _validate_aces_sdl(resolved)
    return resolved


def _resolve_project_file(project_dir: Path, candidate: Path) -> Path:
    """Resolve ``candidate`` and require it to stay within ``project_dir``."""
    project_root = project_dir.resolve()
    absolute = candidate if candidate.is_absolute() else project_root / candidate
    resolved = absolute.resolve(strict=False)
    if not resolved.is_relative_to(project_root):
        raise ValueError(f"Scenario path is outside project: {candidate}")
    if not resolved.is_file():
        raise ValueError(f"Scenario path does not exist or is not a file: {candidate}")
    return resolved


def _validate_aces_sdl(path: Path) -> None:
    """Validate selected SDL through the ACES parser authority."""
    sdl_error, parse_sdl_file = _load_aces_sdl_parser()
    try:
        parse_sdl_file(path)
    except (FileNotFoundError, sdl_error, TypeError, ValueError) as exc:
        raise ValueError(
            f"Selected ACES SDL scenario is invalid: {redact(str(exc))}"
        ) from exc


def _load_aces_sdl_parser() -> tuple[type[Exception], Callable[[Path], object]]:
    """Load the optional ACES SDL parser at validation time."""
    try:
        from aces_sdl import SDLError, parse_sdl_file
    except ImportError as exc:
        raise ValueError(
            f"ACES runtime handoff unavailable: {redact(str(exc))}"
        ) from exc
    return SDLError, parse_sdl_file
