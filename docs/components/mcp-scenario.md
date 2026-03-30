# MCP Scenario Creation Server

The `mcp-scenario` server enables AI agents to create and validate APTL SDL scenarios without access to the APTL source code. It embeds a complete copy of the SDL parser and validator along with reference documentation, examples, and scaffolding tools.

## Purpose

When an AI agent needs to generate a scenario for APTL, it needs to understand the SDL syntax and semantics. The scenario MCP provides everything required:

- **SDL reference** — complete syntax, field types, validation rules
- **Detachable examples** — 6 scenarios demonstrating SDL patterns from minimal to full workflows
- **Validation** — structural (schema) and semantic (cross-references, cycles, IP/CIDR) with detailed error feedback
- **Scaffolding** — commented templates for new scenarios
- **Introspection** — enum values, section references, cross-reference rules

## Architecture

Unlike the other APTL MCP servers (TypeScript, require lab connectivity), `mcp-scenario` is a Python MCP server with no external dependencies beyond `mcp`, `pydantic`, and `pyyaml`. It includes a self-contained copy of the SDL package from `src/aptl/core/sdl/`.

```
mcp/mcp-scenario/
├── src/mcp_scenario/
│   ├── server.py        # FastMCP server (tools, resources, prompts)
│   ├── reference.py     # Full SDL reference documentation
│   ├── examples.py      # 6 detachable example scenarios
│   └── sdl/             # Embedded SDL parser & validator
└── tests/
    └── test_server.py   # 31 tests
```

## Tools

| Tool | Description |
|---|---|
| `validate_scenario` | Full structural + semantic validation of a complete SDL YAML |
| `validate_section` | Structural validation of a single section (no cross-ref checks) |
| `scaffold_scenario` | Generate a commented template with selected sections |
| `get_example_scenario` | Get an example scenario by name |
| `list_example_scenarios` | List all examples with descriptions and pattern tags |
| `get_section_reference` | Detailed docs for a specific SDL section |
| `get_cross_reference_rules` | All 31 cross-reference validation constraints |
| `get_enum_values` | Allowed values for a specific enum type |
| `list_enum_types` | All enum types with values and usage |

## Resources

| URI | Description |
|---|---|
| `sdl://reference` | Complete SDL syntax and semantics reference |
| `sdl://sections` | One-line summary of each section |
| `sdl://examples/index` | Example scenario index |

## Typical Agent Workflow

1. Read `sdl://reference` to understand the language
2. Call `list_example_scenarios` to find relevant patterns
3. Call `get_example_scenario` for a starting point
4. Call `scaffold_scenario` for a template
5. Build the scenario iteratively, calling `validate_section` for each section
6. Call `validate_scenario` on the complete scenario
7. Fix errors using the detailed feedback

## Installation and Running

```bash
cd mcp/mcp-scenario
pip install -e .
aptl-scenario-mcp  # Runs as stdio MCP server
```

## Client Configuration

```json
{
  "mcpServers": {
    "aptl-scenario": {
      "command": "aptl-scenario-mcp"
    }
  }
}
```

## Keeping the Embedded SDL in Sync

The `mcp/mcp-scenario/src/mcp_scenario/sdl/` package is a copy of `src/aptl/core/sdl/` with import paths changed from `aptl.core.sdl` to `mcp_scenario.sdl`. When the main SDL models change, the embedded copy should be updated to match.
