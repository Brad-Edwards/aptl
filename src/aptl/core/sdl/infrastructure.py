"""Infrastructure models — deployment topology.

Maps node names to deployment parameters: instance counts, network
links, dependencies, and IP/CIDR properties. IP validation uses
Python's stdlib ``ipaddress`` module for backend-agnostic networking.

ACL rules adapted from CybORG's ``Subnets.NACLs`` pattern.
"""

from enum import Enum
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any, Optional, Union

from pydantic import Field, field_validator, model_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value

MINIMUM_NODE_COUNT = 1
DEFAULT_NODE_COUNT = 1


class ACLAction(str, Enum):
    """Firewall rule action."""

    ALLOW = "allow"
    DENY = "deny"


class ACLRule(SDLModel):
    """A network access control rule on an infrastructure node.

    Adapted from CybORG's subnet NACL model. Specifies directional
    traffic rules between network segments.
    """

    direction: str = ""
    from_net: str = ""
    to_net: str = ""
    protocol: str = "any"
    ports: list[int] = Field(default_factory=list)
    action: ACLAction = ACLAction.ALLOW
    description: str = ""

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, v: str) -> str:
        return normalize_enum_value(v)


class SimpleProperties(SDLModel):
    """Network properties for a switch/subnet: CIDR, gateway, and flags."""

    cidr: str
    gateway: str
    internal: bool = False

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        ip_network(v, strict=False)
        return v

    @field_validator("gateway")
    @classmethod
    def validate_gateway(cls, v: str) -> str:
        ip_address(v)
        return v

    @model_validator(mode="after")
    def gateway_within_cidr(self) -> "SimpleProperties":
        net = ip_network(self.cidr, strict=False)
        gw = ip_address(self.gateway)
        if gw not in net:
            raise ValueError(
                f"Gateway {self.gateway} is not within CIDR {self.cidr}"
            )
        return self


class InfraNode(SDLModel):
    """Deployment parameters for a node.

    Shorthand: ``node-name: 3`` (just the count).
    Longhand: full dict with count, links, dependencies, properties, acls.
    """

    count: int = Field(default=DEFAULT_NODE_COUNT, ge=MINIMUM_NODE_COUNT)
    links: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    properties: Optional[Union[SimpleProperties, list[dict[str, str]]]] = None
    acls: list[ACLRule] = Field(default_factory=list)
    description: str = ""

    @model_validator(mode="after")
    def validate_unique_links(self) -> "InfraNode":
        if len(self.links) != len(set(self.links)):
            raise ValueError("Infrastructure links must be unique")
        return self

    @model_validator(mode="after")
    def validate_unique_dependencies(self) -> "InfraNode":
        if len(self.dependencies) != len(set(self.dependencies)):
            raise ValueError("Infrastructure dependencies must be unique")
        return self
