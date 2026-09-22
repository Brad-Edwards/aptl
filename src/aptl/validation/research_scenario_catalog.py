"""APTL-owned fixture references used only by explicit research profiles.

This catalog is not a source for ordinary lab selection or acquired-pack
fallback. Profiles additionally bind their selected SDL bytes by SHA-256.
"""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aptl.core.scenario_catalog import ScenarioCatalogEntry
from aptl.utils.pathsafe import read_contained_nofollow


class ResearchScenarioEntry(ScenarioCatalogEntry):
    """One local fixture locator; its profile owns containment and byte checks."""

    path: str = Field(min_length=1)


class ResearchScenarioCatalog(BaseModel):
    """The existing strict fixture index, isolated from the pack catalog."""

    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    scenarios: list[ResearchScenarioEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_ids(self) -> "ResearchScenarioCatalog":
        ids = [entry.id for entry in self.scenarios]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate research scenario id")
        return self

    def get(self, identity: str) -> ResearchScenarioEntry | None:
        return next((entry for entry in self.scenarios if entry.id == identity), None)


def load_research_scenario_catalog(project_root: Path) -> ResearchScenarioCatalog:
    """Read the explicit profile's contained fixture index without following links."""

    return ResearchScenarioCatalog.model_validate_json(
        read_contained_nofollow(project_root, "scenarios/catalog.json")
    )
