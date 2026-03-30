"""Agent models — autonomous participants in the scenario.

Adapted from CybORG's Agents section. An agent has a role (from
entities), available actions, initial authenticated access (via
accounts), initial knowledge of the environment, and network
scope constraints.

The SDL specifies *what's available* to each agent, not *how*
the agent executes. Framework bindings (Gymnasium, PettingZoo)
are a deployment-layer concern.
"""

from pydantic import Field, model_validator

from mcp_scenario.sdl._base import SDLModel


class InitialKnowledge(SDLModel):
    """What an agent knows about the scenario at start time.

    Adapted from CybORG's INT (Initial Network Topology).
    Specifies which hosts, subnets, services, and accounts
    the agent has knowledge of before the scenario begins.
    """

    hosts: list[str] = Field(default_factory=list)
    subnets: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)


class Agent(SDLModel):
    """An autonomous participant in the scenario.

    Agents reference existing scenario elements:
    - ``entity`` links to the entities section (team/role)
    - ``starting_accounts`` links to the accounts section
    - ``allowed_subnets`` links to infrastructure entries
    - ``initial_knowledge`` references nodes and infrastructure
    """

    entity: str = ""
    description: str = ""
    actions: list[str] = Field(default_factory=list)
    starting_accounts: list[str] = Field(default_factory=list)
    initial_knowledge: InitialKnowledge | None = None
    allowed_subnets: list[str] = Field(default_factory=list)
    reward_calculator: str = ""

    @model_validator(mode="after")
    def validate_required_entity(self) -> "Agent":
        if not self.entity:
            raise ValueError("Agent requires 'entity'")
        return self
