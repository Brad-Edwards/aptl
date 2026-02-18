# CLI Reference

The `aptl` CLI is installed with `pip install -e .` and provides lab lifecycle, configuration, container, and scenario management.

## Global Options

| Option | Description |
|--------|-------------|
| `--version`, `-V` | Show version and exit |
| `--help` | Show help |

## aptl lab

Lab lifecycle management.

| Command | Description |
|---------|-------------|
| `aptl lab start` | Start the lab (SSH keys, certs, system checks, MCP builds, containers) |
| `aptl lab stop` | Stop the lab |
| `aptl lab status` | Show running containers and health |

**Options:**

- `--project-dir`, `-d` — Path to the APTL project directory (default: `.`)
- `aptl lab stop --volumes`, `-v` — Also remove Docker volumes (full cleanup)

## aptl config

Configuration management.

| Command | Description |
|---------|-------------|
| `aptl config show` | Display current configuration from `aptl.json` |
| `aptl config validate` | Validate the configuration file |

## aptl container

Container operations.

| Command | Description |
|---------|-------------|
| `aptl container list` | List containers and their status |
| `aptl container logs <name>` | Show logs for a container |

## aptl scenario

Scenario management. See [Scenarios](../usage/scenarios.md) for usage details.

| Command | Description |
|---------|-------------|
| `aptl scenario list` | List available scenarios |
| `aptl scenario show <name>` | Display scenario details |
| `aptl scenario validate <path>` | Validate a scenario YAML file |
| `aptl scenario start <name>` | Start a scenario |
| `aptl scenario status` | Check active scenario progress |
| `aptl scenario evaluate` | Score auto-checkable objectives |
| `aptl scenario hint <objective_id>` | Get a hint for an objective (costs points) |
| `aptl scenario complete <objective_id>` | Manually mark an objective complete |
| `aptl scenario stop` | Stop the active scenario |

**Common options for scenario commands:**

- `--project-dir`, `-d` — Path to the APTL project directory (default: `.`)
- `--scenarios-dir`, `-s` — Path to scenarios directory (default: `<project-dir>/scenarios`)
