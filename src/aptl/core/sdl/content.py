"""Content models — data placed into scenario systems.

Adapted from CyRIS ``copy_content`` and ``emulate_traffic_capture``
patterns. Represents files, datasets (email collections, DB records,
pcap files), and directory structures that exist within scenario
nodes as part of the environment state.

Examples: phishing lure emails in an Exchange mailbox, synthetic
customer records in a database, planted credentials in shared
directories, CTF flag files.
"""

from enum import Enum
from typing import Optional

from pydantic import Field, field_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value, parse_bool_or_var
from aptl.core.sdl._source import Source


class ContentType(str, Enum):
    """Kind of content placed into a system."""

    FILE = "file"
    DATASET = "dataset"
    DIRECTORY = "directory"


class ContentItem(SDLModel):
    """A single item within a dataset (e.g., one email, one record)."""

    name: str
    tags: list[str] = Field(default_factory=list)
    description: str = ""


class Content(SDLModel):
    """Data or files placed into a scenario node.

    Supports three forms:
    - ``file``: A single file at a specific path, optionally with inline text.
    - ``dataset``: A collection of related items (emails, records, pcaps)
      delivered via a source package or listed as items.
    - ``directory``: A directory structure placed at a destination path.
    """

    type: ContentType
    description: str = ""
    target: str = ""
    path: str = ""
    destination: str = ""
    text: Optional[str] = None
    source: Optional[Source] = None
    format: str = ""
    items: list[ContentItem] = Field(default_factory=list)
    sensitive: bool | str = False
    tags: list[str] = Field(default_factory=list)

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return normalize_enum_value(v)

    @field_validator("sensitive", mode="before")
    @classmethod
    def parse_sensitive(cls, v: bool | str) -> bool | str:
        return parse_bool_or_var(v, field_name="sensitive")
