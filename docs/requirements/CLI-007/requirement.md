---
id: CLI-007
title: "Configuration Inspection Command"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 1
created_at: 2026-05-03T04:29:19.070721Z
updated_at: 2026-05-03T06:31:43.762340Z
---

# CLI-007 — Configuration Inspection Command

## Statement

The CLI shall provide an `aptl config show` command that pretty-prints the resolved APTL configuration as loaded by `core/config.find_config()` + `core/config.load_config()`, including default values for any unset fields. The command shall locate the project's `aptl.json` via the same discovery rules used by the rest of the CLI, render the validated `AptlConfig` Pydantic model in a stable human-readable form, and exit with code 0 on success or non-zero with a clear error message when no config is found or loading fails.

## Rationale

CLI-002 covers configuration *validation* but not inspection. Users currently have no way to see the resolved configuration the CLI will use — including defaulted fields — without reading the source. UAT smoke testing (issue #138) flagged `aptl config show` as a stubbed command with no requirement backing it. SYS-006 (Python CLI Control Plane) lists "configuration" as a CLI responsibility but does not mandate a specific show subcommand. Splitting `config show` from CLI-002 keeps the validation requirement focused on its single concern and aligns the CLI subcommand surface with explicit requirements.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/cli/config.py` (aptl config show command)
- IMPLEMENTS → CODE_FILE `src/aptl/cli/_common.py` (resolve_config_for_cli helper)
- TESTS → TEST `tests/test_cli_config.py` (CLI config validate/show tests)
- IMPLEMENTS → GITHUB_ISSUE `138` (Issue 138 — implement stubbed CLI commands)
