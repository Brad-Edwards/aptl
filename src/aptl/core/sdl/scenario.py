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

from aptl.core.sdl._base import SDLModel
from aptl.core.sdl._contracts import sdl_ensure, sdl_require
from aptl.core.sdl.accounts import Account
from aptl.core.sdl.agents import Agent
from aptl.core.sdl.conditions import Condition
from aptl.core.sdl.content import Content
from aptl.core.sdl.entities import Entity
from aptl.core.sdl.features import Feature
from aptl.core.sdl.infrastructure import InfraNode
from aptl.core.sdl.nodes import Node
from aptl.core.sdl.objectives import Objective
from aptl.core.sdl.orchestration import Event, Inject, Script, Story, Workflow, WorkflowStep
from aptl.core.sdl.relationships import Relationship
from aptl.core.sdl.scoring import Evaluation, Goal, Metric, TLO
from aptl.core.sdl.variables import Variable
from aptl.core.sdl.vulnerabilities import Vulnerability


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

    # ------------------------------------------------------------------
    # Stable query boundaries (ADR-014 §"Contract Guards").
    #
    # `icontract.require` asserts the requested name is declared in this
    # scenario; `icontract.ensure` asserts the returned object IS the one
    # keyed by that name (identity, not equality), so callers cannot
    # accidentally splice in an `Objective`/`Workflow`/`WorkflowStep`
    # from a different scenario.
    # ------------------------------------------------------------------

    @sdl_require(
        lambda self, name: name in self.objectives,
        description="objective_is_declared(name)",
    )
    @sdl_ensure(
        lambda self, name, result: result is self.objectives[name],
        description="returned_objective_belongs_to_scenario",
    )
    def get_objective(self, name: str) -> Objective:
        """Return the `Objective` declared under ``name`` in this scenario."""
        return self.objectives[name]

    @sdl_require(
        lambda self, name: name in self.workflows,
        description="workflow_is_declared(name)",
    )
    @sdl_ensure(
        lambda self, name, result: result is self.workflows[name],
        description="returned_workflow_belongs_to_scenario",
    )
    def get_workflow(self, name: str) -> Workflow:
        """Return the `Workflow` declared under ``name`` in this scenario."""
        return self.workflows[name]

    @sdl_require(
        lambda self, workflow_name, step_name: (
            workflow_name in self.workflows
            and step_name in self.workflows[workflow_name].steps
        ),
        description="workflow_step_is_declared(workflow,step)",
    )
    @sdl_ensure(
        lambda self, workflow_name, step_name, result: (
            result is self.workflows[workflow_name].steps[step_name]
        ),
        description="returned_step_belongs_to_workflow",
    )
    def get_workflow_step(
        self, workflow_name: str, step_name: str
    ) -> WorkflowStep:
        """Return the `WorkflowStep` keyed by ``step_name`` in ``workflow_name``."""
        return self.workflows[workflow_name].steps[step_name]
