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
| `aptl doctor` | Check the host and the selected Docker engine before a start, without changing anything. |
| `aptl lab` | Initialize, select, start, inspect, validate, stop, and clean a lab project. |
| `aptl config` | Show and validate the strict, non-secret project configuration. |
| `aptl container` | List realized project containers and open bounded logs or shells. |
| `aptl runs` | List, inspect, locate, export, and verify project run evidence. |
| `aptl web` | Serve the local operator UI and API through the supported single-origin boundary. |
| `aptl kill` | Emergency process and container termination; not normal teardown. |
| `aptl experiment` | Admit experiment inputs and persist an immutable trial plan without executing it. |
| `aptl seat` | Run one disposable appliance seat from a published VM image. |
| `aptl mcp-access` | Materialize authorized MCP client access for a participant or appliance seat. |

`aptl --version` prints the installed CLI version. Hidden implementation flags
and direct calls into Python modules are not supported interfaces.

## First-Lab Commands

| Task | Command | Result |
| --- | --- | --- |
| Create a project | `aptl lab init <directory>` | Materializes the lab assets bundled with the installed release. |
| Check the host | `aptl doctor` | Reports each unmet prerequisite with its fix and exits with status 1 when a check failed. |
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

## Exit Status And JSON Output

`aptl doctor`, `aptl lab start`, `aptl lab status`, and `aptl lab stop` share
one exit status contract. Tests lock it.

| Exit status | Meaning |
| --- | --- |
| `0` | The command did what it reports. `aptl doctor` found no failed check, `aptl lab start` brought the lab up, `aptl lab status` observed the project, and `aptl lab stop` left it stopped, including when it was not running. |
| `1` | The command could not do it. A doctor check failed, the start failed, the project state could not be observed, or the stop failed. |
| `2` | Invalid usage, such as an unknown option, conflicting scenario selectors, or `--json` with `--clean` or `--volumes` but without `--yes`. |

A start that ends `degraded_usable` or `degraded_unusable` still exits with
status 0; read its outcome. With `--json`, `aptl doctor`, `aptl lab start`, and
`aptl lab stop` print one JSON object on standard output, and start progress
goes to standard error. Each object has `command`, `schema_version` (now `1`),
and `ok`, which is `true` exactly when the exit status is `0`. A new field keeps
the schema version; removing or retyping a field raises it. The JSON and text
outputs render the same result.

| Command | Fields after `command`, `schema_version`, and `ok` |
| --- | --- |
| `aptl doctor --json` | `counts`, the number of checks per status (`pass`, `warn`, `fail`, `skip`); `checks`, a list of `id`, `status`, `summary`, and `fix`. |
| `aptl lab start --json` | `outcome` (`ready`, `degraded_usable`, `degraded_unusable`, or `failed`); `error`, a string or `null`; `execution_boundary`, the observed boundary or `null`; `admission_seconds`, a number or `null`; `diagnostics`, a list of `step`, `component`, `impact`, `severity`, `message`, and `operator_action`; `published_ports`, a list of `service`, `default_port`, `host_port`, `protocols`, `host_ip`, and `remapped`; `residue`, `null` or the `container_count`, `network_count`, `teardown_requested`, and `torn_down` of a failed start. |
| `aptl lab stop --json` | `volumes`, whether `--volumes` was requested; `error`, a string or `null`. |

`aptl lab status --json` keeps its existing output, the redacted range
snapshot with `timestamp`, `software`, `containers`, `wazuh_rules`, `networks`,
`config_hashes`, `services`, and `ssh`. It exits with status 1 when the
snapshot can't be captured.

## Destructive And Emergency Operations

`aptl lab stop -v` is the supported full cleanup for one project. It requires
confirmation unless the explicit non-interactive option shown by `--help` is
used. It destroys volume-backed lab data but does not prune unrelated Docker
resources.

`aptl lab start --clean` performs the same project-volume cleanup before a
fresh start. `aptl kill` and its container option are emergency controls for
stuck MCP processes or lab containers. They are not a graceful stop, a data
reset, or a substitute for investigating a failed readiness result.

A failed `aptl lab start` leaves the containers and networks it created in
place so you can diagnose the failure. The failure summary counts them and
names the two recovery commands: `aptl lab stop` keeps the volumes, and
`aptl lab stop -v` destroys all lab data. If you ran the start from outside
its project directory, both commands include `--project-dir`. Add
`--teardown-on-failure` to the start command to stop those containers and
networks automatically instead. It keeps the volumes. An appliance seat's
guest readiness publication runs after the lab is up, so if it fails, the
summary doesn't count the containers and networks and `--teardown-on-failure`
doesn't stop them.

## Configuration And Secrets

`aptl.json` holds validated, durable, non-secret project configuration. Runtime
credentials and generated client configuration stay in private project files,
including `.env` and `.mcp.json`. Use `aptl config validate` for the former and
`aptl lab info` for safe access discovery. Never paste generated files into an
issue, command line, or documentation example.
