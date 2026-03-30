#!/usr/bin/env python3
"""APTL Scenario Creation MCP Server.

Provides tools for AI agents to create, validate, and understand APTL SDL
scenarios without access to the APTL source code. Includes:

- Full SDL reference documentation (as a resource)
- Detachable example scenarios
- Validation with detailed feedback
- Section-level schema introspection
- Scaffold generation for new scenarios
"""

import json
import textwrap
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from mcp_scenario.examples import EXAMPLES, get_example, list_examples
from mcp_scenario.reference import SDL_REFERENCE, SECTION_SUMMARIES
from mcp_scenario.sdl import SDLParseError, SDLValidationError, parse_sdl

mcp = FastMCP(
    "APTL Scenario SDL",
    instructions=(
        "This server helps you create and validate APTL SDL scenarios. "
        "Start by reading the SDL reference (sdl-reference resource) to "
        "understand the language. Use the examples to see patterns. "
        "Use validate_scenario to check your work iteratively."
    ),
)


# ── Resources ──────────────────────────────────────────────────────────


@mcp.resource("sdl://reference")
def sdl_reference() -> str:
    """Complete APTL SDL syntax and semantics reference.

    Read this first to understand the scenario description language.
    Covers all 21 sections, cross-reference rules, shorthand forms,
    and validation constraints.
    """
    return SDL_REFERENCE


@mcp.resource("sdl://sections")
def sdl_sections() -> str:
    """One-line summary of each SDL section.

    Quick reference for what each of the 21 sections does.
    """
    lines = []
    for i, (name, desc) in enumerate(SECTION_SUMMARIES.items(), 1):
        lines.append(f"{i:2d}. {name}: {desc}")
    return "\n".join(lines)


@mcp.resource("sdl://examples/index")
def examples_index() -> str:
    """List of available example scenarios with descriptions and pattern tags."""
    examples = list_examples()
    lines = []
    for ex in examples:
        lines.append(f"### {ex['name']}")
        lines.append(f"**Patterns**: {ex['patterns']}")
        lines.append(f"{ex['description']}")
        lines.append("")
    return "\n".join(lines)


# ── Tools ──────────────────────────────────────────────────────────────


@mcp.tool()
def validate_scenario(sdl_yaml: str) -> str:
    """Validate an SDL scenario YAML string.

    Runs both structural validation (Pydantic model parsing, type checking,
    enum validation) and semantic validation (cross-reference integrity,
    cycle detection, IP/CIDR consistency, domain rules).

    Returns either a success message with scenario summary and any advisories,
    or detailed error messages explaining exactly what needs to be fixed.

    Args:
        sdl_yaml: The complete SDL scenario as a YAML string.
    """
    try:
        scenario = parse_sdl(sdl_yaml)
    except SDLParseError as e:
        return _format_parse_error(e)
    except SDLValidationError as e:
        return _format_validation_error(e)

    # Build summary
    sections_used = []
    for section_name in SECTION_SUMMARIES:
        value = getattr(scenario, section_name, None)
        if value and isinstance(value, dict) and len(value) > 0:
            sections_used.append(f"  {section_name}: {len(value)} entries")

    summary = [
        f"VALID scenario: {scenario.name}",
        f"Description: {scenario.description or '(none)'}",
        "",
        "Sections populated:",
        *sections_used,
    ]

    if scenario.advisories:
        summary.append("")
        summary.append("Advisories (non-fatal warnings):")
        for adv in scenario.advisories:
            summary.append(f"  - {adv}")

    return "\n".join(summary)


@mcp.tool()
def validate_section(section_name: str, section_yaml: str) -> str:
    """Validate a single SDL section in isolation.

    Wraps the section in a minimal scenario (just name + the section)
    and runs structural validation only (no cross-reference checks).
    Useful for iteratively building a scenario section by section.

    Args:
        section_name: The SDL section name (e.g., "nodes", "features").
        section_yaml: The YAML content for just that section.
    """
    valid_sections = set(SECTION_SUMMARIES.keys())
    if section_name not in valid_sections:
        return (
            f"Unknown section '{section_name}'. "
            f"Valid sections: {', '.join(sorted(valid_sections))}"
        )

    try:
        section_data = yaml.safe_load(section_yaml)
    except yaml.YAMLError as e:
        return f"YAML parse error in {section_name}:\n{e}"

    if section_data is None:
        return f"Section '{section_name}' is empty (parsed as None)."

    wrapper = {"name": f"__validation__{section_name}", section_name: section_data}
    wrapper_yaml = yaml.dump(wrapper, default_flow_style=False)

    try:
        parse_sdl(wrapper_yaml, skip_semantic_validation=True)
    except SDLParseError as e:
        return _format_parse_error(e, section_context=section_name)
    except SDLValidationError as e:
        return _format_validation_error(e, section_context=section_name)

    entry_count = len(section_data) if isinstance(section_data, dict) else "N/A"
    return (
        f"Section '{section_name}' is structurally valid. "
        f"Entries: {entry_count}. "
        f"Note: cross-reference checks require a full scenario."
    )


@mcp.tool()
def get_example_scenario(name: str) -> str:
    """Get a complete example SDL scenario by name.

    Returns the full YAML along with a description of what patterns
    it demonstrates. Use list_examples first to see available options.

    Args:
        name: Example name (e.g., "minimal", "simple-webapp-pentest").
    """
    example = get_example(name)
    if example is None:
        available = ", ".join(EXAMPLES.keys())
        return f"Example '{name}' not found. Available: {available}"

    return (
        f"# Example: {name}\n"
        f"# {example['description']}\n"
        f"# Patterns: {example['patterns']}\n"
        f"\n{example['sdl']}"
    )


@mcp.tool()
def list_example_scenarios() -> str:
    """List all available example scenarios with descriptions and pattern tags.

    Use this to find examples that demonstrate specific SDL patterns.
    """
    examples = list_examples()
    lines = []
    for ex in examples:
        lines.append(f"- **{ex['name']}**: {ex['description']}")
        lines.append(f"  Patterns: {ex['patterns']}")
    return "\n".join(lines)


@mcp.tool()
def get_section_reference(section_name: str) -> str:
    """Get detailed reference documentation for a specific SDL section.

    Returns the relevant portion of the SDL reference for the named
    section, including syntax, fields, types, rules, and examples.

    Args:
        section_name: The SDL section name (e.g., "nodes", "agents").
    """
    valid_sections = set(SECTION_SUMMARIES.keys())
    if section_name not in valid_sections:
        return (
            f"Unknown section '{section_name}'. "
            f"Valid sections: {', '.join(sorted(valid_sections))}"
        )

    # Extract the relevant section from the reference
    # Section headers in the reference use "### N. section_name"
    section_map = {
        "nodes": "1. nodes",
        "infrastructure": "2. infrastructure",
        "features": "3. features",
        "conditions": "4. conditions",
        "vulnerabilities": "5. vulnerabilities",
        "metrics": "6. metrics",
        "evaluations": "7. evaluations",
        "tlos": "8. tlos",
        "goals": "9. goals",
        "entities": "10. entities",
        "injects": "11. injects",
        "events": "12. events",
        "scripts": "13. scripts",
        "stories": "14. stories",
        "content": "15. content",
        "accounts": "16. accounts",
        "relationships": "17. relationships",
        "agents": "18. agents",
        "objectives": "19. objectives",
        "workflows": "20. workflows",
        "variables": "21. variables",
    }

    header = f"### {section_map[section_name]}"
    start = SDL_REFERENCE.find(header)
    if start == -1:
        return f"Section '{section_name}': {SECTION_SUMMARIES[section_name]}"

    # Find the next section header or end of section reference
    next_header = SDL_REFERENCE.find("\n### ", start + len(header))
    cross_ref_header = SDL_REFERENCE.find("\n## Cross-Reference Rules", start)

    if next_header != -1 and (cross_ref_header == -1 or next_header < cross_ref_header):
        end = next_header
    elif cross_ref_header != -1:
        end = cross_ref_header
    else:
        end = len(SDL_REFERENCE)

    return SDL_REFERENCE[start:end].strip()


@mcp.tool()
def scaffold_scenario(
    scenario_name: str,
    description: str = "",
    sections: list[str] | None = None,
) -> str:
    """Generate a scaffold YAML for a new scenario with commented guidance.

    Creates a starting template with the requested sections pre-populated
    with example entries and inline comments explaining each field.

    Args:
        scenario_name: Name for the new scenario.
        description: Optional description.
        sections: List of section names to include (e.g., ["nodes",
            "infrastructure", "features"]). If omitted, includes all sections.
    """
    valid_sections = list(SECTION_SUMMARIES.keys())
    if sections is None:
        sections = valid_sections
    else:
        invalid = [s for s in sections if s not in valid_sections]
        if invalid:
            return (
                f"Unknown sections: {', '.join(invalid)}. "
                f"Valid: {', '.join(valid_sections)}"
            )

    lines = [
        f"name: {scenario_name}",
    ]
    if description:
        lines.append(f"description: >")
        lines.append(f"  {description}")
    lines.append("")

    scaffolds = _get_section_scaffolds()
    for section in sections:
        if section in scaffolds:
            lines.append(scaffolds[section])
            lines.append("")

    return "\n".join(lines)


@mcp.tool()
def get_cross_reference_rules() -> str:
    """Get the complete list of cross-reference validation rules.

    Returns all 31 cross-reference constraints the semantic validator
    enforces. Essential reading before building scenarios with
    inter-section references.
    """
    start = SDL_REFERENCE.find("## Cross-Reference Rules")
    if start == -1:
        return "Cross-reference rules section not found."

    end = SDL_REFERENCE.find("\n## ", start + 1)
    if end == -1:
        end = len(SDL_REFERENCE)

    return SDL_REFERENCE[start:end].strip()


@mcp.tool()
def get_enum_values(enum_name: str) -> str:
    """Get allowed values for an SDL enum type.

    Args:
        enum_name: Name of the enum (e.g., "NodeType", "OSFamily",
            "FeatureType", "RelationshipType", "ExerciseRole",
            "PasswordStrength", "ContentType", "MetricType",
            "VariableType", "WorkflowStepType", "SuccessMode",
            "AssetValueLevel", "ACLAction").
    """
    from mcp_scenario.sdl.nodes import NodeType, OSFamily, AssetValueLevel
    from mcp_scenario.sdl.features import FeatureType
    from mcp_scenario.sdl.conditions import Condition  # noqa: F401
    from mcp_scenario.sdl.vulnerabilities import Vulnerability  # noqa: F401
    from mcp_scenario.sdl.scoring import MetricType
    from mcp_scenario.sdl.entities import ExerciseRole
    from mcp_scenario.sdl.orchestration import WorkflowStepType
    from mcp_scenario.sdl.content import ContentType
    from mcp_scenario.sdl.accounts import PasswordStrength
    from mcp_scenario.sdl.relationships import RelationshipType
    from mcp_scenario.sdl.objectives import SuccessMode
    from mcp_scenario.sdl.variables import VariableType
    from mcp_scenario.sdl.infrastructure import ACLAction

    enums: dict[str, Any] = {
        "NodeType": NodeType,
        "OSFamily": OSFamily,
        "AssetValueLevel": AssetValueLevel,
        "FeatureType": FeatureType,
        "MetricType": MetricType,
        "ExerciseRole": ExerciseRole,
        "WorkflowStepType": WorkflowStepType,
        "ContentType": ContentType,
        "PasswordStrength": PasswordStrength,
        "RelationshipType": RelationshipType,
        "SuccessMode": SuccessMode,
        "VariableType": VariableType,
        "ACLAction": ACLAction,
    }

    if enum_name not in enums:
        available = ", ".join(sorted(enums.keys()))
        return f"Unknown enum '{enum_name}'. Available: {available}"

    enum_cls = enums[enum_name]
    values = [f"  - {member.value}" for member in enum_cls]
    return f"{enum_name} values:\n" + "\n".join(values)


@mcp.tool()
def list_enum_types() -> str:
    """List all SDL enum types and their allowed values.

    Returns every enum used in the SDL with all accepted values.
    """
    from mcp_scenario.sdl.nodes import NodeType, OSFamily, AssetValueLevel
    from mcp_scenario.sdl.features import FeatureType
    from mcp_scenario.sdl.scoring import MetricType
    from mcp_scenario.sdl.entities import ExerciseRole
    from mcp_scenario.sdl.orchestration import WorkflowStepType
    from mcp_scenario.sdl.content import ContentType
    from mcp_scenario.sdl.accounts import PasswordStrength
    from mcp_scenario.sdl.relationships import RelationshipType
    from mcp_scenario.sdl.objectives import SuccessMode
    from mcp_scenario.sdl.variables import VariableType
    from mcp_scenario.sdl.infrastructure import ACLAction

    enums = [
        ("NodeType", NodeType, "Node.type"),
        ("OSFamily", OSFamily, "Node.os"),
        ("AssetValueLevel", AssetValueLevel, "AssetValue.confidentiality/integrity/availability"),
        ("FeatureType", FeatureType, "Feature.type"),
        ("MetricType", MetricType, "Metric.type"),
        ("ExerciseRole", ExerciseRole, "Entity.role"),
        ("WorkflowStepType", WorkflowStepType, "WorkflowStep.type"),
        ("ContentType", ContentType, "Content.type"),
        ("PasswordStrength", PasswordStrength, "Account.password_strength"),
        ("RelationshipType", RelationshipType, "Relationship.type"),
        ("SuccessMode", SuccessMode, "ObjectiveSuccess.mode"),
        ("VariableType", VariableType, "Variable.type"),
        ("ACLAction", ACLAction, "ACLRule.action"),
    ]

    lines = []
    for name, enum_cls, usage in enums:
        values = ", ".join(m.value for m in enum_cls)
        lines.append(f"- **{name}** (used in {usage}): {values}")
    return "\n".join(lines)


# ── Prompts ────────────────────────────────────────────────────────────


@mcp.prompt()
def create_scenario(
    scenario_type: str = "general",
    complexity: str = "medium",
) -> str:
    """Guide for creating a new SDL scenario.

    Args:
        scenario_type: Type of scenario (e.g., "ransomware", "apt",
            "insider-threat", "red-vs-blue", "ctf").
        complexity: Desired complexity (simple, medium, complex).
    """
    return textwrap.dedent(f"""\
        You are creating an APTL SDL scenario.

        Scenario type: {scenario_type}
        Complexity: {complexity}

        Follow this workflow:
        1. Read the SDL reference (sdl://reference resource)
        2. Look at relevant examples (list_example_scenarios, then get_example_scenario)
        3. Start with a scaffold (scaffold_scenario tool)
        4. Build iteratively, validating each section (validate_section tool)
        5. Validate the complete scenario (validate_scenario tool)
        6. Fix any errors — the validator gives detailed feedback

        Key principles:
        - Every cross-reference must resolve (node features → features section, etc.)
        - Infrastructure entries must match node names
        - Infrastructure links must reference switch nodes
        - Feature dependencies cannot form cycles
        - Objective dependencies cannot form cycles
        - Workflow graphs must be acyclic and fully reachable from start

        For {complexity} complexity:
        {"- Just nodes, infrastructure, and features" if complexity == "simple" else
         "- Include scoring pipeline (metrics → evaluations → TLOs → goals)" if complexity == "medium" else
         "- Full scenario with agents, objectives, workflows, and variables"}
    """)


# ── Helpers ────────────────────────────────────────────────────────────


def _format_parse_error(
    e: SDLParseError, section_context: str = ""
) -> str:
    ctx = f" in section '{section_context}'" if section_context else ""
    lines = [f"STRUCTURAL ERROR{ctx}:", ""]
    details = e.details if hasattr(e, "details") else str(e)

    # Try to make Pydantic errors more readable
    if "validation error" in details.lower():
        lines.append("The YAML structure doesn't match the SDL schema:")
        lines.append("")
        for line in details.split("\n"):
            line = line.strip()
            if line:
                lines.append(f"  {line}")
    else:
        lines.append(details)

    lines.append("")
    lines.append(
        "Tip: Use get_section_reference to see the expected structure, "
        "or validate_section to check one section at a time."
    )
    return "\n".join(lines)


def _format_validation_error(
    e: SDLValidationError, section_context: str = ""
) -> str:
    ctx = f" in section '{section_context}'" if section_context else ""
    count = len(e.errors)
    lines = [
        f"SEMANTIC VALIDATION: {count} error{'s' if count != 1 else ''}{ctx}:",
        "",
    ]
    for i, err in enumerate(e.errors, 1):
        lines.append(f"  {i}. {err}")

    lines.append("")
    lines.append(
        "Tip: Use get_cross_reference_rules to see all validation constraints."
    )
    return "\n".join(lines)


def _get_section_scaffolds() -> dict[str, str]:
    """Return scaffold YAML snippets for each section."""
    return {
        "nodes": textwrap.dedent("""\
            # --- Nodes: VMs and network switches ---
            nodes:
              # Network segments (type: Switch)
              corp-net:
                type: Switch
                description: Corporate network segment

              # Virtual machines (type: VM)
              server-01:
                type: VM
                os: linux                    # windows, linux, macos, freebsd, other
                source: ubuntu-22.04         # Image/template reference
                resources:
                  ram: 4 GiB                 # Human-readable: GiB, MiB, GB, etc.
                  cpu: 2                     # Integer >= 1
                features:                    # feature-name: role-name
                  # my-feature: my-role
                conditions:                  # condition-name: role-name
                  # my-check: my-role
                services:
                  - {port: 443, name: https, protocol: tcp}
                roles:
                  my-role:
                    username: admin"""),
        "infrastructure": textwrap.dedent("""\
            # --- Infrastructure: deployment topology ---
            infrastructure:
              corp-net:
                count: 1
                properties:
                  cidr: 10.0.0.0/24
                  gateway: 10.0.0.1
                  internal: true
              server-01:
                count: 1
                links: [corp-net]            # Must reference switch nodes
                # dependencies: [other-node] # Boot ordering
                properties:
                  - corp-net: 10.0.0.10      # IP within linked CIDR"""),
        "features": textwrap.dedent("""\
            # --- Features: software deployed onto VMs ---
            features:
              my-feature:
                type: Service                # Service, Configuration, or Artifact
                source: my-package           # Optional image/package ref
                # dependencies: [other-feat] # Feature dependency chain
                description: A deployed service"""),
        "conditions": textwrap.dedent("""\
            # --- Conditions: monitoring checks ---
            conditions:
              my-check:
                command: "curl -sf http://localhost/ || exit 1"
                interval: 30                 # Seconds (>= 1)
                # timeout: 10               # Optional
                # retries: 3                # Optional"""),
        "vulnerabilities": textwrap.dedent("""\
            # --- Vulnerabilities: CWE-classified weaknesses ---
            vulnerabilities:
              my-vuln:
                name: Example Vulnerability
                description: Description of the vulnerability
                technical: true
                class: CWE-89               # Must match CWE-NNN format"""),
        "metrics": textwrap.dedent("""\
            # --- Metrics: scoring (conditional or manual) ---
            metrics:
              auto-metric:
                type: conditional
                max-score: 100
                condition: my-check          # Must exist in conditions
              manual-metric:
                type: manual
                max-score: 50
                artifact: true               # Optional, manual only"""),
        "evaluations": textwrap.dedent("""\
            # --- Evaluations: metric groups with thresholds ---
            evaluations:
              my-eval:
                metrics: [auto-metric, manual-metric]
                min-score: 60                # Shorthand for {percentage: 60}"""),
        "tlos": textwrap.dedent("""\
            # --- TLOs: Training Learning Objectives ---
            tlos:
              my-tlo:
                name: My learning objective
                evaluation: my-eval          # Must exist in evaluations"""),
        "goals": textwrap.dedent("""\
            # --- Goals: high-level composed of TLOs ---
            goals:
              my-goal:
                tlos: [my-tlo]               # Must exist in tlos"""),
        "entities": textwrap.dedent("""\
            # --- Entities: teams, orgs, people (recursive) ---
            entities:
              blue-team:
                name: Blue Team
                role: blue                   # white, green, red, blue
                mission: Defend the network
                entities:                    # Nested (ref as blue-team.analyst)
                  analyst:
                    name: SOC Analyst
              red-team:
                name: Red Team
                role: red
                mission: Penetrate the target"""),
        "injects": textwrap.dedent("""\
            # --- Injects: actions between entities ---
            injects:
              my-inject:
                from_entity: red-team        # Must be a defined entity
                to_entities: [blue-team]     # Must be defined entities
                description: An exercise inject"""),
        "events": textwrap.dedent("""\
            # --- Events: triggered actions ---
            events:
              my-event:
                conditions: [my-check]       # Condition names
                injects: [my-inject]         # Inject names"""),
        "scripts": textwrap.dedent("""\
            # --- Scripts: timed event sequences ---
            scripts:
              my-script:
                start-time: 0
                end-time: 2 hour
                speed: 1.0
                events:
                  my-event: 30 min           # event: time (within bounds)"""),
        "stories": textwrap.dedent("""\
            # --- Stories: top-level orchestration ---
            stories:
              my-story:
                scripts: [my-script]"""),
        "content": textwrap.dedent("""\
            # --- Content: data placed into systems ---
            content:
              my-dataset:
                type: dataset                # file, dataset, or directory
                target: server-01            # Must be a VM node
                format: csv
                source: sample-data
                sensitive: true
                tags: [pii]"""),
        "accounts": textwrap.dedent("""\
            # --- Accounts: user accounts on nodes ---
            accounts:
              my-account:
                username: admin
                node: server-01              # Must be a VM node
                groups: [Admins]
                password_strength: medium     # weak, medium, strong, none"""),
        "relationships": textwrap.dedent("""\
            # --- Relationships: typed edges between elements ---
            relationships:
              my-rel:
                type: connects_to            # See RelationshipType enum
                source: server-01            # Any named element
                target: my-feature           # Any named element"""),
        "agents": textwrap.dedent("""\
            # --- Agents: autonomous participants ---
            agents:
              my-agent:
                entity: red-team             # Must be a defined entity
                actions: [Scan, Exploit]
                allowed_subnets: [corp-net]  # Switch infrastructure names
                initial_knowledge:
                  hosts: [server-01]
                  subnets: [corp-net]"""),
        "objectives": textwrap.dedent("""\
            # --- Objectives: declarative experiment goals ---
            objectives:
              my-objective:
                agent: my-agent              # OR entity: red-team (not both)
                actions: [Scan]              # Subset of agent's actions
                targets: [server-01]
                success:
                  conditions: [my-check]     # At least one ref required"""),
        "workflows": textwrap.dedent("""\
            # --- Workflows: control-flow graphs ---
            workflows:
              my-workflow:
                start: step-1
                steps:
                  step-1:
                    type: objective
                    objective: my-objective
                    next: done
                  done:
                    type: end"""),
        "variables": textwrap.dedent("""\
            # --- Variables: scenario parameterization ---
            variables:
              my_var:
                type: string                 # string, integer, boolean, number
                default: "value"
                description: A configurable parameter
                # allowed_values: ["a", "b"]
                # required: false"""),
    }


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
