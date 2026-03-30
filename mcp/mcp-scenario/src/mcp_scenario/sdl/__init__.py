"""Embedded APTL Scenario Description Language (SDL) parser and validator.

This is a self-contained copy of the SDL package from the main APTL
codebase, so the MCP server can run without access to the APTL source.

Public API:
    parse_sdl(content) -> Scenario
    Scenario — top-level model (21 sections)
    SDLParseError — YAML/structural errors
    SDLValidationError — semantic validation errors
"""

from mcp_scenario.sdl._errors import SDLError, SDLParseError, SDLValidationError
from mcp_scenario.sdl.parser import parse_sdl
from mcp_scenario.sdl.scenario import Scenario

__all__ = [
    "parse_sdl",
    "Scenario",
    "SDLError",
    "SDLParseError",
    "SDLValidationError",
]
