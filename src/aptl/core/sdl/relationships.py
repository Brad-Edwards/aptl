"""Relationship models — typed directed edges between scenario elements.

Adapted from STIX 2.1 Relationship SROs and OCR's dependency patterns.
Provides a general-purpose mechanism for expressing how services,
nodes, and accounts relate to each other — authentication chains,
trust relationships, federation, and connectivity.

This is how identity emerges in the SDL: accounts describe *who*,
features describe *what provides auth*, and relationships describe
*how they connect*.
"""

from enum import Enum

from pydantic import Field, field_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value


class RelationshipType(str, Enum):
    """How two scenario elements relate to each other."""

    AUTHENTICATES_WITH = "authenticates_with"
    TRUSTS = "trusts"
    FEDERATES_WITH = "federates_with"
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    MANAGES = "manages"
    REPLICATES_TO = "replicates_to"


class Relationship(SDLModel):
    """A typed directed edge between two named scenario elements.

    Source and target can reference any named element in the scenario:
    nodes, features, accounts, entities, or infrastructure entries.
    The validator checks that both endpoints resolve.

    The ``properties`` dict carries type-specific metadata (e.g.,
    ``trust_type: parent-child`` for AD trusts, ``protocol: SAML``
    for federation). It's a flat dict rather than typed sub-models
    because relationship properties vary widely and we don't want
    to gate expressiveness on pre-modeling every variant.
    """

    type: RelationshipType
    source: str
    target: str
    description: str = ""
    properties: dict[str, str] = Field(default_factory=dict)

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return normalize_enum_value(v)
