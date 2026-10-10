# Deployment And Lifecycle

APTL supports a released local project, a source checkout for contributors,
and a prebuilt disposable appliance. All three use the CLI lifecycle boundary;
raw Compose commands are not an equivalent deployment path.

## Released Local Project

Install the released package and materialize its lab assets:

```shell
pipx install aptl-labs
aptl lab init my-lab
cd my-lab
aptl lab start --scenario techvault
```

The project directory owns its `aptl.json`, generated private state, run store,
and Docker resources. Keep lifecycle commands rooted in that directory, or use
their documented project-directory option.

`aptl lab start` performs the deployment work as one operation: it validates
configuration and scenario input, realizes the topology, generates project
credentials and service configuration, resolves host ports, builds required
MCP artifacts, starts containers, waits for required readiness, updates client
configuration, and records the run.

Do not replace it with `docker compose up`. That bypasses control-plane work
needed by a fresh project and can start a topology that does not match the
selected scenario.

## Source Checkout

A source checkout is for contributors. Follow the
[contribution setup](https://github.com/OpenRAE/lilrae/blob/dev/CONTRIBUTING.md#development-setup)
to create a virtual environment and editable install. The checkout itself is
the project directory; do not run `aptl lab init` over it.

## Disposable Appliance

The appliance path puts rootful Docker and the complete lab inside a disposable
KVM guest booted from a published image. See the
[appliance seat launcher](reference/appliance-seat-launcher.md) for operator
use, including how updates are adopted and rolled back.

Offline appliance startup accepts only the staged wheels, project assets, and
OCI images bound by its launch descriptor and trust anchors. Missing inputs
fail closed instead of pulling or building from the network.

## Configuration

`aptl.json` is the strict, non-secret project configuration. Inspect and
validate it through the CLI:

```shell
aptl config show
aptl config validate
```

Scenario selection belongs to the acquired environment-pack catalog, not an
ad hoc list of enabled containers. Use `aptl lab scenarios` and pass a catalog
identity to `aptl lab start --scenario <id>`. Project-local SDL paths are an
explicit development surface.

Runtime credentials and generated client bindings belong in private files such
as `.env` and `.mcp.json`; they are not `aptl.json` fields and must not be
committed. Wazuh `INDEXER_*` and `API_*` values are credentials declared by the
admitted scenario, not APTL control-plane or operator login credentials.

### Scenario Environment Grants

A scenario node can declare runtime environment variables. These rules cover
both node realization routes (see
[Node Realization Routes](components/node-realization.md)): a base-container
node, which declares runtime desired state and has no node image of its own, so
APTL starts it from a base image, and an image-backed node, which runs as a
service of the Compose model that APTL generates for the scenario. On either
route, APTL delivers each variable from a single explicit source:

- A value the scenario authors is delivered exactly as written.
- A generated-artifact output reaches only the node that declares it with
  `value_from`.
- An `operator_secret`, `redacted` or `secret_fixture` variable declared
  without a value needs an environment grant in `aptl.json` or a value that the
  admitted pack's own startup adapter supplies.
- Any other variable declared without a value is delivered empty, even when the
  image sets a default for it. That is the value RAES expects such a
  declaration to have.

**This changes earlier behavior.** APTL used to fill a declared variable from
any same-named variable in its own process environment or in `.env`, and a
shell variable overrode an authored value. A matching name is not authority to
read a credential, so neither happens now. If you passed a value to a scenario
node by exporting it before `aptl lab start`, or by adding it to `.env`, add a
grant. A value-less variable that is not `operator_secret`, `redacted` or
`secret_fixture` takes no grant, so the scenario must author its value or give
it one of those classifications. A missing or empty source stops
`aptl lab start` before realization creates or changes any scenario network,
volume or container. The error names the node and the variable, and either the
pack, when no grant or adapter value applies, or the source that has no value.

**The `docker compose` process no longer inherits APTL's whole environment.**
It keeps the Docker client's own settings, such as `PATH`, `HOME`,
`DOCKER_HOST`, `DOCKER_CONTEXT`, `SSL_CERT_FILE`, Compose client options like
`COMPOSE_HTTP_TIMEOUT`, and proxy variables. It also keeps the `APTL_*`
settings, such as the `APTL_HP_*` host-port pins, and the `BUILDKIT_*` and
`BUILDX_*` build settings. Any other `${NAME}` in a Compose file therefore
resolves only from the project `.env`. A shell variable no longer overrides a
`.env` value such as `GRAFANA_ADMIN_PASSWORD` or `INDEXER_PASSWORD`, so change
the value in `.env` instead.

A Compose service receives each grant or startup-adapter value through its own
owner-only env file under `.aptl/realization/sourced-environment/`, which a
generated override attaches to that service alone. That file cannot carry a
value that contains a single quote or ends in an odd number of backslashes, so
such a value stops `aptl lab start` at the same point as a missing source. The
value is never written as a `${NAME}` reference. Compose resolves those
references from one environment that every service and every Compose file of
the project share, so a reference would let a value granted to one node reach
another service, or APTL's own Grafana. An in-tree scenario that ships its own
`docker-compose.yml` keeps its own references, resolved from `.env`.

In the Compose model that APTL generates, no text that the scenario or its
pack authors names a variable for Compose to fill. APTL writes each `$` in such
text as `$$`, which Compose reads as one literal `$`. This covers a command, an
environment value, a mount path, a content destination, the name of a file in
a pack directory, an image reference and a host address. A
`${INDEXER_PASSWORD}` in a node's command or in a content path therefore
reaches the container as written instead of as the `.env` value, and a
container-shell `"$@"` reaches the shell unchanged.

A grant names the admitted pack's identifier, the consuming node, the variable
that node declares, and the source. The source is either an exact variable of
the process that runs `aptl lab start`, or an exact key of the project `.env`:

```json
{
  "deployment": {
    "environment_grants": [
      {
        "pack": "example-pack",
        "consumer": "webapp",
        "variable": "DB_PASSWORD",
        "source": {"kind": "process-environment", "variable": "LAB_DB_PASSWORD"}
      },
      {
        "pack": "example-pack",
        "consumer": "worker",
        "variable": "API_TOKEN",
        "source": {"kind": "project-env-file", "variable": "WORKER_API_TOKEN"}
      }
    ]
  }
}
```

A grant applies only to the pack, node and variable it names. A project-tree
scenario has no pack identity, so no grant applies to it. `aptl lab start`
reads each grant's source once, when it checks the scenario, and logs a warning
for a grant that matches no value-less secret. Logs and errors name each source,
such as `grant:process-environment:LAB_DB_PASSWORD`, and never its value.
`aptl.json` stores only these names.

## Observe A Deployment

Use APTL's runtime projections after startup:

```shell
aptl lab status
aptl lab info
aptl container list
```

`aptl lab status` reports current running and container state. The structured
`aptl lab start` result remains the readiness authority. `aptl lab info` prints
URLs, remapped host ports, usernames, and credential locations for the realized
scenario. `aptl container list` reports project-owned containers. These results
replace fixed port, service, and credential tables.

Both `lab start` and `lab info` print a separate execution-boundary observation:
selected transport, whether the daemon appears native, VM-backed, remote or
unknown, and whether an override selected the endpoint. `info` re-observes the
backend even when `.env` is absent. Unknown or conflicting facts are reported
as such. A remote daemon's published ports belong to its host; the CLI does not
claim they are reachable on the operator's `localhost`. This host-boundary
observation is separate from RAES-authored scenario VM/container requirements
and is disclosed in RAES-validated backend-owned `ApplyResult.details` for a run.
See [tested profiles and limits](getting-started/prerequisites.md#tested-execution-profiles-and-limits).

Inspect one realized service with:

```shell
aptl container logs <container-name>
aptl container shell <container-name>
```

Use a name returned by `aptl container list`. A container in Docker's `running`
state does not by itself prove that the scenario is ready.

## Manage The Lifecycle

```shell
aptl lab start --scenario <id>  # validate, realize, start, and await readiness
aptl lab status                 # inspect lifecycle and realized state
aptl lab info                   # discover current access information
aptl lab stop                   # stop while preserving volumes
aptl lab stop -v                # confirm and destroy project volumes
aptl lab start --clean --scenario <id>  # confirm a clean boot
```

Lifecycle mutations are single-owner per project. If another start, stop,
clean boot, policy tick, or container kill owns the project, a second mutation
fails without removing resources under the active operation. Wait for the
owner to finish, or stop it and use `aptl lab stop` to reconcile the project.

`aptl lab stop -v` also clears host-side state that described the removed
volumes, such as the Wazuh agent enrollment baseline. That cleanup is recorded
at start and survives APTL upgrades. If Docker teardown fails, or the volumes
are gone but host cleanup remains, the stop names the failed step and the
retry command. See [pending host cleanup](troubleshooting/index.md#aptl-lab-stop-v-reports-pending-host-cleanup).

`aptl kill` is an emergency process-control surface. It is not normal teardown,
a data reset, or a replacement for the structured startup result.

## Automatic Lifecycle Policy

APTL can enforce project time-to-live, idle-timeout, and scheduled provisioning
rules declared in the validated `lifecycle_policy` configuration. Inspect the
installed command contract before enabling automation:

```shell
aptl lab policy --help
aptl lab enforce --help
aptl lab monitor --help
```

Policy actions use the same per-project lifecycle lock as manual and API
operations, so they cannot interleave with another mutation. See
[ADR-045](adrs/adr-045-ephemeral-lifecycle-policy-enforcement.md) for the
design and failure model.

## Recovery

Use the project-scoped sequence first:

```shell
aptl lab stop
aptl lab start --scenario <id>
```

Use `aptl lab stop -v` only when you intend to destroy the project's
volume-backed data. Do not use daemon-wide prune commands as routine recovery;
they can remove images, caches, networks, and volumes owned by unrelated
projects.

Continue with the [troubleshooting guide](troubleshooting/index.md) for
component diagnostics and platform-specific failures.
