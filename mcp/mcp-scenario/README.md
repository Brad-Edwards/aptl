# APTL Scenario Creation MCP Server

An MCP (Model Context Protocol) server that enables AI agents to create and validate APTL SDL (Scenario Description Language) scenarios. Fully self-contained — includes the SDL parser, validator, reference documentation, and examples with no dependency on the main APTL codebase.

## What It Provides

| Capability | How |
|---|---|
| **SDL Reference** | Complete syntax/semantics docs as an MCP resource |
| **Validation** | Full structural + semantic validation with detailed error messages |
| **Examples** | 6 detachable scenarios demonstrating different SDL patterns |
| **Scaffolding** | Template generation for new scenarios |
| **Introspection** | Enum values, section references, cross-reference rules |

## Installation

```bash
cd mcp/mcp-scenario
pip install -e .
```

## Running

```bash
# As a stdio MCP server (for IDE/agent integration)
aptl-scenario-mcp

# Or directly
python -m mcp_scenario.server
```

## MCP Client Configuration

Add to your MCP client settings (e.g., Claude Desktop, VS Code):

```json
{
  "mcpServers": {
    "aptl-scenario": {
      "command": "aptl-scenario-mcp",
      "args": []
    }
  }
}
```

Or if running from the repo:

```json
{
  "mcpServers": {
    "aptl-scenario": {
      "command": "python",
      "args": ["-m", "mcp_scenario.server"],
      "cwd": "/path/to/aptl/mcp/mcp-scenario"
    }
  }
}
```

## Tools

### `validate_scenario`
Validates a complete SDL scenario YAML string. Runs both structural validation (Pydantic schema) and semantic validation (cross-references, cycles, IP ranges, etc.). Returns either a success summary or detailed error messages.

### `validate_section`
Validates a single SDL section in isolation (structural only, no cross-reference checks). Useful for iteratively building a scenario section by section.

### `get_example_scenario`
Returns a complete example scenario by name with description and pattern tags.

### `list_example_scenarios`
Lists all available examples with descriptions and the SDL patterns they demonstrate.

### `scaffold_scenario`
Generates a commented YAML template for a new scenario with selected sections.

### `get_section_reference`
Returns detailed reference documentation for a specific SDL section.

### `get_cross_reference_rules`
Returns all 31 cross-reference constraints enforced by the semantic validator.

### `get_enum_values`
Returns allowed values for a specific SDL enum type (e.g., NodeType, RelationshipType).

### `list_enum_types`
Lists all SDL enum types with their allowed values and where they're used.

## Resources

| URI | Description |
|---|---|
| `sdl://reference` | Complete SDL syntax and semantics reference |
| `sdl://sections` | One-line summary of each of the 21 sections |
| `sdl://examples/index` | Index of available example scenarios |

## Prompts

### `create_scenario`
Guided workflow for creating a new scenario. Parameters:
- `scenario_type`: ransomware, apt, insider-threat, red-vs-blue, ctf
- `complexity`: simple, medium, complex

## Examples

The server includes 6 built-in examples at increasing complexity:

1. **minimal** — Just a name (simplest valid scenario)
2. **simple-webapp-pentest** — Nodes, infrastructure, scoring pipeline
3. **orchestrated-exercise** — Injects, events, scripts, stories with timing
4. **agents-and-objectives** — Autonomous agents with dependency chains
5. **variables-and-content** — Parameterization, content placement, relationships
6. **workflow-branching** — Control flow: if/then/else, parallel, end nodes

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Architecture

```
mcp/mcp-scenario/
├── pyproject.toml
├── README.md
├── src/mcp_scenario/
│   ├── __init__.py
│   ├── server.py          # MCP server (tools, resources, prompts)
│   ├── reference.py        # SDL reference documentation
│   ├── examples.py         # Detachable example scenarios
│   └── sdl/                # Embedded SDL parser & validator
│       ├── __init__.py
│       ├── _base.py         # Base model, variable helpers
│       ├── _errors.py       # SDLParseError, SDLValidationError
│       ├── _source.py       # Source reference type
│       ├── parser.py        # YAML → Scenario (normalization, shorthands)
│       ├── validator.py     # Semantic validation (cross-refs, cycles)
│       ├── scenario.py      # Top-level Scenario model
│       ├── nodes.py         # VM/Switch models
│       ├── infrastructure.py # Topology models
│       ├── features.py      # Feature models
│       ├── conditions.py    # Condition models
│       ├── vulnerabilities.py # Vulnerability models
│       ├── scoring.py       # Metrics/Evaluations/TLOs/Goals
│       ├── entities.py      # Entity hierarchy
│       ├── orchestration.py # Injects/Events/Scripts/Stories/Workflows
│       ├── content.py       # Content models
│       ├── accounts.py      # Account models
│       ├── relationships.py # Relationship models
│       ├── agents.py        # Agent models
│       ├── objectives.py    # Objective models
│       └── variables.py     # Variable models
└── tests/
    └── test_server.py       # 31 tests
```

The `sdl/` package is a self-contained copy of `src/aptl/core/sdl/` with import paths updated. This allows the MCP server to run independently of the APTL installation.
