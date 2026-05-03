"""APTL Scenario Description Language (SDL).

A backend-agnostic scenario specification language ported from the
Open Cyber Range SDL and extended with sections for content, accounts,
relationships, agents, objectives, workflows, and variables.

Public API:
    parse_sdl(content) -> Scenario
    parse_sdl_file(path) -> Scenario
    Scenario — top-level model (21 sections)
    SDLParseError — YAML/structural errors
    SDLValidationError — semantic validation errors
"""

from aptl.core.sdl._errors import SDLError, SDLParseError, SDLValidationError
from aptl.core.sdl.parser import parse_sdl, parse_sdl_file
from aptl.core.sdl.scenario import Scenario

__all__ = [
    "parse_sdl",
    "parse_sdl_file",
    "Scenario",
    "SDLError",
    "SDLParseError",
    "SDLValidationError",
]
