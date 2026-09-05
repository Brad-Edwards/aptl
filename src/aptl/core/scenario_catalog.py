"""Operator catalog projected from the configured acquired environment pack."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aptl.backends._raes_scenario_resolution import resolve_scenario_bundle
from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.scenario_bundle import EnvPackError, PackIdentity, ScenarioBundle
from aptl.core.scenarios import ScenarioNotFoundError, ScenarioValidationError
from aptl.utils.pathsafe import (
    REASON_DOT_COMPONENT,
    REASON_EMPTY_COMPONENT,
    REASON_NOT_RELATIVE,
    REASON_NUL_BYTE,
    REASON_TRAVERSAL,
    PathContainmentError,
    open_contained_nofollow,
)
from aptl.utils.redaction import redact

_OUTSIDE_PROJECT_REASONS = frozenset(
    {
        REASON_NOT_RELATIVE,
        REASON_TRAVERSAL,
        REASON_NUL_BYTE,
        REASON_EMPTY_COMPONENT,
        REASON_DOT_COMPONENT,
    }
)
_SCENARIO_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class ScenarioCatalogMetadata(BaseModel):
    """Narrow optional display facts that do not redefine pack semantics."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["red", "blue", "purple"] | None = None
    difficulty: Literal["beginner", "intermediate", "advanced", "expert"] | None = None
    estimated_minutes: int | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("estimated_minutes")
    @classmethod
    def validate_estimated_minutes(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("estimated_minutes must be a positive integer")
        return value


class ScenarioCatalogEntry(BaseModel):
    """One operator-facing selector projected from env-packs' catalog model."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    metadata: ScenarioCatalogMetadata | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _SCENARIO_ID.fullmatch(value):
            raise ValueError("invalid scenario id")
        return value


@dataclass(frozen=True)
class ScenarioCatalog:
    """A catalog and the validated acquired identity it was projected from."""

    scenarios: tuple[ScenarioCatalogEntry, ...]
    pack_identity: PackIdentity
    maturity: str
    bundle: ScenarioBundle
    version: int = 1

    def get(self, scenario_id: str) -> ScenarioCatalogEntry | None:
        return next((entry for entry in self.scenarios if entry.id == scenario_id), None)


@dataclass(frozen=True)
class ResolvedScenario:
    """One parsed catalog selection bound to its validated acquired bundle."""

    entry: ScenarioCatalogEntry
    scenario: object
    bundle: ScenarioBundle
    maturity: str


def _config(project_dir: Path) -> AptlConfig:
    config_path = find_config(project_dir)
    return load_config(config_path) if config_path is not None else AptlConfig()


def _known_text(value: object) -> str:
    if isinstance(value, dict) and value.get("state") == "known":
        text = value.get("value")
        return text if isinstance(text, str) else ""
    return ""


def _entry_from_projection(raw: dict[str, object]) -> ScenarioCatalogEntry:
    pack_id = str(raw.get("name") or "")
    title = str(raw.get("title") or pack_id)
    return ScenarioCatalogEntry(
        id=pack_id,
        name=title,
        description=_known_text(raw.get("purpose")),
    )


def load_scenario_catalog(
    project_dir: Path, *, config: AptlConfig | None = None
) -> ScenarioCatalog:
    """Stage the configured pack once and project env-packs' catalog read model."""
    selected = config or _config(project_dir)
    if selected.scenario.source != "env-pack":
        raise ValueError("scenario catalog requires an acquired env-pack source")
    try:
        bundle = resolve_scenario_bundle(project_dir, None, selected)
        identity = bundle.pack_identity
        if identity is None:
            raise ValueError("acquired scenario has no validated pack identity")
        from raes_env_packs.catalog import Source, build_catalog

        document, diagnostics = build_catalog(
            [
                Source(
                    id=identity.pack_id,
                    revision=identity.set_digest,
                    root=str(bundle.root),
                )
            ],
            as_of=date.today().isoformat(),
        )
    except (EnvPackError, ImportError, OSError, TypeError, ValueError) as exc:
        raise ValueError(
            f"Acquired scenario catalog unavailable: {redact(str(exc))}"
        ) from exc
    blocking = [diagnostic for diagnostic in diagnostics if diagnostic.blocking]
    if blocking or len(document.entries) != 1:
        raise ValueError("Acquired scenario catalog failed validation")
    raw = document.entries[0]
    return ScenarioCatalog(
        scenarios=(_entry_from_projection(raw),),
        pack_identity=identity,
        maturity=str(raw.get("maturity") or "unknown"),
        bundle=bundle,
    )


def resolve_scenario_selection(
    project_dir: Path,
    *,
    scenario_id: str | None = None,
    scenario_path: Path | None = None,
) -> Path | None:
    """Validate a pack selector or an explicit contained development SDL path."""
    if scenario_id and scenario_path is not None:
        raise ValueError("scenario selectors are mutually exclusive")
    if not scenario_id and scenario_path is None:
        return None
    if scenario_id:
        selected = _config(project_dir).scenario
        available = selected.identity if selected.source == "env-pack" else "none"
        if scenario_id != available:
            raise ValueError(
                f"Unknown scenario id '{scenario_id}'. Available scenarios: {available}"
            )
        return None
    assert scenario_path is not None
    resolved = _resolve_project_file(project_dir, scenario_path)
    _validate_raes_sdl(resolved)
    return resolved


def _resolve_project_file(project_dir: Path, candidate: Path) -> Path:
    """Resolve an explicit development scenario without following symlinks."""
    project_root = project_dir.resolve()
    if candidate.is_absolute():
        try:
            relative = candidate.relative_to(project_root)
        except ValueError as exc:
            raise ValueError(f"Scenario path is outside project: {candidate}") from exc
    else:
        relative = candidate
    try:
        handle = open_contained_nofollow(project_root, relative)
    except PathContainmentError as exc:
        if exc.reason in _OUTSIDE_PROJECT_REASONS:
            raise ValueError(f"Scenario path is outside project: {candidate}") from exc
        raise ValueError(
            f"Scenario path does not exist or is not a file: {candidate}"
        ) from exc
    handle.close()
    return project_root / relative


def resolve_acquired_scenario(
    project_dir: Path,
    scenario_id: str,
    *,
    catalog: ScenarioCatalog | None = None,
) -> ResolvedScenario:
    """Resolve, validate, and parse one acquired catalog selection once."""
    try:
        selected_catalog = catalog or load_scenario_catalog(project_dir)
    except ValueError as exc:
        raise ScenarioValidationError(redact(str(exc))) from exc
    entry = selected_catalog.get(scenario_id)
    if entry is None:
        raise ScenarioNotFoundError(scenario_id)
    try:
        scenario = _parse_raes_sdl(selected_catalog.bundle.sdl_path)
    except ValueError as exc:
        raise ScenarioValidationError(redact(str(exc))) from exc
    return ResolvedScenario(
        entry, scenario, selected_catalog.bundle, selected_catalog.maturity
    )


def resolve_and_parse_scenario(
    project_dir: Path, scenario_id: str
) -> tuple[ScenarioCatalogEntry, object]:
    """Compatibility projection returning the entry and parsed RAES scenario."""
    resolved = resolve_acquired_scenario(project_dir, scenario_id)
    return resolved.entry, resolved.scenario


def _validate_raes_sdl(path: Path) -> None:
    _parse_raes_sdl(path)


def _parse_raes_sdl(path: Path) -> object:
    sdl_error, parse_sdl_file = _load_raes_sdl_parser()
    try:
        return parse_sdl_file(path)
    except (FileNotFoundError, sdl_error, TypeError, ValueError) as exc:
        raise ValueError(
            f"Selected RAES SDL scenario is invalid: {redact(str(exc))}"
        ) from exc


def _load_raes_sdl_parser():
    try:
        from raes import SDLError, parse_sdl_file
    except ImportError as exc:
        raise ValueError(
            f"RAES runtime handoff unavailable: {redact(str(exc))}"
        ) from exc
    return SDLError, parse_sdl_file
