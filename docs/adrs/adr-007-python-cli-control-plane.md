# ADR-007: Python CLI as Primary Control Plane

> Historical note: references to `aptl scenario` in this ADR describe the retired pre-SDL runtime, not the current SDL-only branch.

## Status

accepted

## Date

2026-02-07

## Context

From v2.0 through v3.x, the lab lifecycle was managed by `start-lab.sh` — a 273-line bash script that handled SSH key generation, environment setup, certificate management, Docker Compose orchestration, credential synchronization, and health checking. While functional, it had accumulated serious limitations:

### Problems with start-lab.sh

1. **No error handling**: Commands that failed silently left the lab in an inconsistent state. A failed certificate generation didn't stop the startup sequence — containers would start without valid certs and fail with cryptic TLS errors.

2. **No parallelism**: Every operation ran sequentially. Docker image pulling, health checking, and SSH testing all blocked the main thread. Startup took longer than necessary.

3. **No state management**: The script had no concept of lab state. Running it twice could produce duplicate certificate generation, conflicting Docker Compose processes, or orphaned containers. There was no `stop` or `status` command.

4. **Only 4 of 9 profiles**: The script hardcoded `--profile` flags for only 4 Docker Compose profiles (wazuh, victim, kali, reverse). As the SOC stack and enterprise infrastructure were added, the script couldn't deploy them. Users had to manually add `--profile soc --profile enterprise` flags.

5. **No configuration validation**: The script read `aptl.json` for container enable/disable state but didn't validate the configuration. Invalid JSON, missing fields, or impossible combinations (SOC without Wazuh) passed silently.

6. **Bash limitations**: Complex operations like NDJSON parsing (`docker compose ps --format json` outputs one JSON object per line, not a JSON array), credential file manipulation with regex, and structured logging were awkward or fragile in bash.

### Requirements

- Start, stop, and status commands with proper lifecycle management
- Configuration validation before deployment
- Structured error handling — fail early, report clearly
- All Docker Compose profiles supported via `aptl.json`
- Health check orchestration that waits for dependencies
- SSH connectivity verification
- Credential synchronization across Wazuh components
- SSL certificate generation/management
- Extensible for future commands (`aptl scenario`, `aptl config`)

## Decision

Implement a Python CLI (`aptl`) as the primary control plane, replacing `start-lab.sh`.

### Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| CLI framework | **Typer** | Declarative command definitions, auto-generated help, type annotations for argument validation |
| Configuration | **Pydantic** | Schema validation, type coercion, clear error messages for invalid configs |
| Output | **Rich** | Colored terminal output, progress indicators, tables — without manual ANSI escape codes |
| Structure | **src layout** | `src/aptl/` package with `pyproject.toml`. Standard Python packaging. |

### Architecture

```
src/aptl/
├── cli/              # Thin CLI layer (typer commands)
│   ├── main.py       # aptl entry point
│   ├── lab.py        # aptl lab start|stop|status
│   ├── scenario.py   # aptl scenario start|stop|list
│   ├── container.py  # aptl container list|shell|logs
│   └── config.py     # aptl config show|validate
├── core/             # Domain logic (no CLI dependencies)
│   ├── lab.py        # Lab lifecycle: start, stop, status, orchestration
│   ├── config.py     # Pydantic models: AptlConfig, ContainerConfig
│   ├── env.py        # .env file management, EnvVars
│   ├── ssh.py        # SSH key generation (Ed25519)
│   ├── certs.py      # SSL certificate generation via Docker
│   ├── credentials.py # Wazuh credential synchronization
│   ├── services.py   # Health checks, readiness probes
│   ├── sysreqs.py    # System requirements (vm.max_map_count)
│   ├── snapshot.py   # Range snapshot capture
│   └── scenario.py   # Scenario engine
└── utils/
    └── logging.py    # Structured logging
```

The separation between `cli/` and `core/` is intentional — the core domain logic has no dependency on Typer, Rich, or terminal I/O. This enables:

- **Testing**: Core functions are testable without mocking CLI frameworks
- **Reuse**: The future web UI backend ([ADR-011](adr-011-web-ui.md)) shares the same `core/` modules
- **Scripting**: Core functions can be imported directly for custom automation

### 12-Step Lab Orchestration

`aptl lab start` executes a deterministic sequence:

1. Load and validate configuration (`aptl.json`)
2. Load environment variables (`.env`)
3. Check system requirements (`vm.max_map_count >= 262144`)
4. Generate SSH keys (Ed25519, if not present)
5. Generate SSL certificates (via Docker container, if not present)
6. Synchronize credentials to Wazuh config files
7. Pre-pull Docker images (with progress visibility)
8. Start containers via `docker compose up --build -d` with profile flags
9. Wait for Wazuh Indexer to be healthy
10. Wait for Wazuh Manager API to be ready
11. Test SSH connectivity to all SSH-enabled containers (with retry: 60s timeout, 5s interval)
12. Capture range snapshot

Each step reports its status and fails the entire sequence on error, with a clear message about what went wrong and how to fix it.

### Test Coverage

587+ tests across 12 test files covering all core modules. Tests use mocking for Docker and subprocess calls to run without a live lab environment.

### Security Guardrail: Project-Rooted Credential Writes

Wazuh credential synchronization is part of lab startup and writes only the
known in-repository config files under `config/wazuh_dashboard/` and
`config/wazuh_cluster/`. The synchronization API should own construction of
those known relative paths from the caller's `project_dir`, resolve the target,
and reject any path that is not contained by the resolved project root before
reading or writing.

Do not expose arbitrary caller-provided output paths for these credential
writers. If future startup steps need to write project-owned files, keep the
same boundary: accept a project root plus a hardcoded project-relative target,
validate containment at the core-module boundary, then perform I/O.

## Consequences

### Positive

- **Reliable startup**: Every step validates its preconditions and reports failures clearly
- **All profiles supported**: `aptl.json` configuration drives which profiles are activated — all 6 profile groups work
- **Extensible**: Adding `aptl scenario start/stop` was straightforward because the core domain logic was already separated
- **Testable**: 587+ tests provide confidence in orchestration logic, credential handling, certificate management
- **Shared core**: Web UI backend can import `src/aptl/core/` directly instead of shelling out to the CLI

### Negative

- **Python dependency**: Users must have Python 3.11+ and install the package (`pip install -e .`). The bash script had no dependencies beyond Docker.
- **Two systems**: `start-lab.sh` was retained as an alternative through v4.2.1, creating confusion about which was authoritative. It was removed in v4.2.2.
- **Startup overhead**: Python interpreter startup adds ~1 second vs. bash. Negligible compared to Docker operations but noticeable for `aptl --help`.

### Risks

- The `subprocess.run()` calls to `docker compose` are a fragile interface — changes to Docker Compose's CLI, output format, or exit codes can break the orchestration. The NDJSON parsing bug (v4.5.0) was an example.
- Credential synchronization uses regex to modify Wazuh configuration XML files. A polynomial backtracking (ReDoS) vulnerability was found and fixed in v4.6.5. XML manipulation via regex remains fragile.
- The 12-step sequence is serial. Steps 7-12 could potentially be parallelized for faster startup, but the dependency ordering makes this non-trivial.
