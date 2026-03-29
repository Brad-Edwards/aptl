"""Condition models — monitoring checks run on VMs.

A condition is either command-based (command + interval) or
source-based (a library package). The two forms are mutually
exclusive, enforced by a model validator.
"""

from typing import Optional

from pydantic import Field, model_validator

from aptl.core.sdl._base import SDLModel
from aptl.core.sdl._source import Source


class Condition(SDLModel):
    """A monitoring check deployed to a VM.

    Either ``command`` + ``interval`` or ``source`` must be set, not both.
    """

    name: str = ""
    command: Optional[str] = None
    interval: Optional[int] = Field(default=None, ge=1)
    timeout: Optional[int] = Field(default=None, ge=1)
    retries: Optional[int] = Field(default=None, ge=0)
    start_period: Optional[int] = Field(default=None, ge=0)
    source: Optional[Source] = None
    description: str = ""
    environment: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_command_xor_source(self) -> "Condition":
        has_command = self.command is not None
        has_interval = self.interval is not None
        has_source = self.source is not None

        if has_command and has_source:
            raise ValueError(
                "Condition cannot have both 'command' and 'source'"
            )
        if has_command and not has_interval:
            raise ValueError(
                "Condition with 'command' requires 'interval'"
            )
        if has_interval and not has_command:
            raise ValueError(
                "Condition with 'interval' requires 'command'"
            )
        if not has_command and not has_source:
            raise ValueError(
                "Condition must have either 'command' + 'interval' or 'source'"
            )
        return self
