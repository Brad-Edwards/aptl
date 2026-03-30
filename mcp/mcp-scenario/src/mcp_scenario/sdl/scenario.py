"""Top-level Scenario model — the root of the SDL.

The Scenario combines 21 specification sections covering
who (entities, accounts, agents), what (nodes, features,
vulnerabilities, content), when (scripts, stories, events),
and declarative experiment semantics (objectives, scoring
pipeline, conditions, relationships, workflows, variables).

Delivery-level concerns (Docker, Terraform, cloud APIs) are
outside the SDL.
"""

from pydantic import Field, PrivateAttr

from mcp_scenario.sdl._base import SDLModel
from mcp_scenario.sdl.accounts import Account
from mcp_scenario.sdl.agents import Agent
from mcp_scenario.sdl.conditions import Condition
from mcp_scenario.sdl.content import Content
from mcp_scenario.sdl.entities import Entity
from mcp_scenario.sdl.features import Feature
from mcp_scenario.sdl.infrastructure import InfraNode
from mcp_scenario.sdl.nodes import Node
from mcp_scenario.sdl.objectives import Objective
from mcp_scenario.sdl.orchestration import Event, Inject, Script, Story, Workflow
from mcp_scenario.sdl.relationships import Relationship
from mcp_scenario.sdl.scoring import Evaluation, Goal, Metric, TLO
from mcp_scenario.sdl.variables import Variable
from mcp_scenario.sdl.vulnerabilities import Vulnerability


class Scenario(SDLModel):
    """Top-level scenario specification.

    A YAML document with up to 21 named sections. Only ``name``
    is required. All sections are optional dicts keyed by
    user-defined identifiers.
    """

    # --- Identity ---
    name: str
    description: str = ""

    # --- OCR SDL: 14 sections ---
    nodes: dict[str, Node] = Field(default_factory=dict)
    infrastructure: dict[str, InfraNode] = Field(default_factory=dict)
    features: dict[str, Feature] = Field(default_factory=dict)
    conditions: dict[str, Condition] = Field(default_factory=dict)
    vulnerabilities: dict[str, Vulnerability] = Field(default_factory=dict)
    metrics: dict[str, Metric] = Field(default_factory=dict)
    evaluations: dict[str, Evaluation] = Field(default_factory=dict)
    tlos: dict[str, TLO] = Field(default_factory=dict)
    goals: dict[str, Goal] = Field(default_factory=dict)
    entities: dict[str, Entity] = Field(default_factory=dict)
    injects: dict[str, Inject] = Field(default_factory=dict)
    events: dict[str, Event] = Field(default_factory=dict)
    scripts: dict[str, Script] = Field(default_factory=dict)
    stories: dict[str, Story] = Field(default_factory=dict)

    # --- Extended sections ---
    content: dict[str, Content] = Field(default_factory=dict)
    accounts: dict[str, Account] = Field(default_factory=dict)
    relationships: dict[str, Relationship] = Field(default_factory=dict)
    agents: dict[str, Agent] = Field(default_factory=dict)
    objectives: dict[str, Objective] = Field(default_factory=dict)
    workflows: dict[str, Workflow] = Field(default_factory=dict)
    variables: dict[str, Variable] = Field(default_factory=dict)

    _advisories: list[str] = PrivateAttr(default_factory=list)

    @property
    def advisories(self) -> list[str]:
        """Non-fatal SDL advisories gathered during semantic validation."""
        return list(self._advisories)

    def _set_advisories(self, advisories: list[str]) -> None:
        self._advisories = list(advisories)
