# Run Your First Lab

Start in the project directory created by `aptl lab init`. If you do not have
one yet, follow [Installation](installation.md).

## Choose The Execution Boundary

`aptl lab start` runs intentionally vulnerable containers and agent tools on
the selected Docker engine. Use it for supervised work on a dedicated,
rebuildable machine. Do not treat an everyday workstation containing unrelated
credentials or workloads as disposable lab infrastructure.

For agent-driven or multi-user work on Linux/KVM, the disposable
[`aptl seat start`](../reference/appliance-seat-launcher.md) path provides a
stronger VM boundary around Docker and the lab. Neither containers nor a VM
are an absolute sandbox. Keep the host kernel and hypervisor current and
control the surrounding network.

## Choose A Scenario

List the validated scenarios supplied by the installed environment pack:

```shell
aptl lab scenarios
```

For the standard released lab, select the `techvault` catalog identity. Use
the identifiers printed by the command rather than a copied list: availability
and qualification belong to the installed pack version.

An explicit `--scenario-path` is a development surface for a project-local SDL
file. It is not the normal released-package path.

## Start And Verify The Lab

Start the selected scenario:

```shell
aptl lab start --scenario techvault
```

Startup validates the project and scenario, prepares keys and certificates,
realizes the requested topology, starts its containers and MCP artifacts, and
waits for required readiness checks. Read the final structured result. A
container shown as running is not by itself proof that the scenario is ready.

Verify the current state and print runtime-derived access information:

```shell
aptl lab status
aptl lab info
```

If startup reports `degraded` or `failed`, follow its named diagnostic before
starting an exercise. The [troubleshooting guide](../troubleshooting/index.md)
shows the safe inspection and recovery commands.

## Inspect The Running Lab

The realized scenario determines which services exist. Discover them at
runtime:

```shell
aptl container list
aptl lab info
```

`aptl lab info` reports current URLs, remapped host ports, usernames, and the
project-local locations of credentials. Read the values from your own project;
do not use a password or port copied from documentation.

Open the Wazuh Dashboard or another realized service at the URL printed by
`aptl lab info`. For a shell in a listed container, use:

```shell
aptl container shell aptl-victim
aptl container shell aptl-kali
```

Only use a container name that appears in `aptl container list` for the
selected scenario.

## Generate Safe Test Activity

Generate activity only inside the authorized lab range. A simple local event
from a realized victim shell is enough to verify the telemetry path:

```shell
logger "APTL first-lab test event"
exit
```

Use the [lab walkthrough](../workshop/walkthrough.md) for a complete guided
exercise. It pairs activity with observations and keeps target selection inside
the realized scenario. Do not copy lab commands to systems outside the range.

## Inspect Results

Use the SOC interfaces reported by `aptl lab info` to inspect alerts and
service data. APTL also records scenario runs in the project-local run store:

```shell
aptl runs list
aptl runs show <run-id>
aptl runs path <run-id>
```

The commands distinguish runtime health, service observations, and archived
run evidence. Use `aptl runs export-bundle <run-id>` when you need a portable,
self-describing evidence bundle; see the
[evidence bundle reference](../reference/evidence-bundle-export.md).

## Stop Or Reset The Lab

Use normal, project-scoped teardown at the end of a session:

```shell
aptl lab stop
```

This stops the realized lab while preserving its Docker volumes. To remove the
project's volumes and all data they contain, use the explicit destructive path:

```shell
aptl lab stop -v
```

The command asks for confirmation and destroys lab indexes, tool data, and
other volume-backed state. It does not remove unrelated Docker resources.

`aptl kill` is an emergency process-control command, not normal teardown or a
credential reset. Do not use `docker system prune` for APTL cleanup; it is
daemon-wide rather than project-scoped.

## Continue From Here

- [CLI reference](../reference/cli.md)
- [MCP reference](../reference/mcp.md)
- [Web reference](../reference/web.md)
- [Troubleshooting](../troubleshooting/index.md)
