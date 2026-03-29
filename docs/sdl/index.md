# Scenario Description Language (SDL) Reference

The APTL SDL is a YAML-based specification language for describing cyber range scenarios. It starts from the [Open Cyber Range SDL](https://github.com/Open-Cyber-Range/SDL-parser) surface, preserves coverage across the OCR-derived sections, and extends that base with APTL's additional scenario concepts such as content, accounts, relationships, agents, and variables. It is intentionally its own SDL rather than a clone-level compatibility layer.

The SDL describes *what a scenario is* — not how to deploy it. A separate backend binding layer (not yet implemented) translates SDL specifications into concrete infrastructure (Docker Compose, Terraform, cloud APIs).

## Stable IDs, Variable Values

The SDL keeps its **symbol table** concrete at parse time. User-defined identifiers such as node keys, feature keys, account keys, relationship keys, entity keys, and other named mapping keys are part of the language structure and must be literal.

Variables are for **attribute values** on already-declared things. That includes fields such as counts, ports, CIDRs, paths, timings, descriptions, and similar runtime-substituted values.

In other words:

- `nodes: {web: ...}` — `web` is a stable SDL identifier
- `content.hostname-file.text: ${hostname}` — `${hostname}` is a variable-backed attribute value

This means a hostname, IP, path, or display string can be variable-backed, but a node cannot be created or renamed through `${...}` inside a mapping key.

## Quick Example

```yaml
name: simple-pentest-lab
description: Web app with SQL injection targeting a database

nodes:
  lab-net:
    type: Switch
  webapp:
    type: VM
    os: linux
    resources: {ram: 2 gib, cpu: 1}
    features: [flask-app]
    services: [{port: 8080, name: http}]
    vulnerabilities: [sqli]
  database:
    type: VM
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: [postgres]
    services: [{port: 5432, name: postgresql}]
    asset_value: {confidentiality: high}

infrastructure:
  lab-net: {count: 1, properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}}
  webapp: {count: 1, links: [lab-net]}
  database: {count: 1, links: [lab-net]}

features:
  flask-app: {type: Service, source: vulnerable-flask-app}
  postgres: {type: Service, source: postgresql-16}

vulnerabilities:
  sqli:
    name: SQL Injection
    description: SQLi in login form
    technical: true
    class: CWE-89

relationships:
  app-to-db:
    type: connects_to
    source: flask-app
    target: postgres

accounts:
  db-admin:
    username: admin
    node: database
    password_strength: weak
```

## Documentation

- [SDL Sections Reference](sections.md) — Complete reference for all 19 sections
- [Parser Behavior](parser.md) — Key normalization, shorthand expansion, SDL-only parsing
- [Semantic Validation](validation.md) — Cross-reference checks and what the validator enforces
- [Design Precedents](precedents.md) — Where each SDL element comes from
- [Limitations & Future Work](limitations.md) — What the SDL cannot express yet
- [Testing](testing.md) — How to run unit tests, stress tests, and fuzz tests

## Usage

```python
from aptl.core.sdl import parse_sdl, parse_sdl_file

# From a string
scenario = parse_sdl(yaml_string)

# From a file
scenario = parse_sdl_file(Path("scenarios/my-scenario.yaml"))

# Skip semantic validation (structural only)
scenario = parse_sdl(yaml_string, skip_semantic_validation=True)
```

## Backward Compatibility

This branch is intentionally SDL-only. Legacy APTL scenario YAMLs (the old `metadata` + `mode` + `objectives` format) no longer parse, and `aptl.core.scenarios` is now a thin SDL loader/error layer rather than a re-export shim.
