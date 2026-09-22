# CLI Reference

The `aptl` command is the supported control plane for a lab project. Run
commands from the project directory created by `aptl lab init`, or pass the
documented project-directory option where one exists.

Use the installed command help for the exact options in your release:

```shell
aptl --help
aptl <command> --help
aptl <command> <subcommand> --help
```

## Command Groups

| Command | Supported behavior |
| --- | --- |
| `aptl lab` | Initialize, select, start, inspect, validate, stop, and clean a lab project. |
| `aptl config` | Show and validate the strict, non-secret project configuration. |
| `aptl container` | List realized project containers and open bounded logs or shells. |
| `aptl runs` | List, inspect, locate, export, and verify project run evidence. |
| `aptl web` | Serve the local operator UI and API through the supported single-origin boundary. |
| `aptl kill` | Emergency process and container termination; not normal teardown. |
| `aptl experiment` | Admit experiment inputs and persist an immutable trial plan without executing it. |
| `aptl appliance` | Build, qualify, stage, and inspect disposable appliance releases. |
| `aptl seat` | Create and manage isolated local appliance seats on supported KVM hosts. |
| `aptl mcp-access` | Materialize authorized MCP client access for a participant or appliance seat. |

`aptl --version` prints the installed CLI version. Hidden implementation flags
and direct calls into Python modules are not supported interfaces.

## First-Lab Commands

| Task | Command | Result |
| --- | --- | --- |
| Create a project | `aptl lab init <directory>` | Materializes the lab assets bundled with the installed release. |
| Discover scenarios | `aptl lab scenarios` | Lists validated identities from the installed environment pack. |
| Start | `aptl lab start --scenario <id>` | Validates and realizes the scenario, starts services, and reports readiness. |
| Check state | `aptl lab status` | Reports the current project lifecycle and realized containers. |
| Discover access | `aptl lab info` | Prints runtime URLs, remapped ports, usernames, and credential locations. |
| List containers | `aptl container list` | Lists containers owned by the realized project. |
| Inspect runs | `aptl runs list` | Lists recent run records in the project-local run store. |
| Stop | `aptl lab stop` | Stops the project while preserving volumes. |
| Reset | `aptl lab stop -v` | Stops the project and, after confirmation, destroys its volumes. |

The CLI result is authoritative. Do not infer readiness from `docker ps`, use a
hard-coded port, or substitute raw `docker compose up` for `aptl lab start`.
The control plane owns scenario realization, generated configuration, port
selection, readiness, MCP setup, and run recording.

## Destructive And Emergency Operations

`aptl lab stop -v` is the supported full cleanup for one project. It requires
confirmation unless the explicit non-interactive option shown by `--help` is
used. It destroys volume-backed lab data but does not prune unrelated Docker
resources.

`aptl lab start --clean` performs the same project-volume cleanup before a
fresh start. `aptl kill` and its container option are emergency controls for
stuck MCP processes or lab containers. They are not a graceful stop, a data
reset, or a substitute for investigating a failed readiness result.

## Configuration And Secrets

`aptl.json` holds validated, durable, non-secret project configuration. Runtime
credentials and generated client configuration stay in private project files,
including `.env` and `.mcp.json`. Use `aptl config validate` for the former and
`aptl lab info` for safe access discovery. Never paste generated files into an
issue, command line, or documentation example.
