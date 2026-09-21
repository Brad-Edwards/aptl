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
[contribution setup](https://github.com/Brad-Edwards/aptl/blob/dev/CONTRIBUTING.md#development-setup)
to create a virtual environment and editable install. The checkout itself is
the project directory; do not run `aptl lab init` over it.

## Disposable Appliance

The appliance path puts rootful Docker and the complete lab inside a disposable
KVM guest. See the [appliance seat launcher](reference/appliance-seat-launcher.md)
for operator use and the [appliance release reference](reference/appliance-release.md)
for signed payload creation, staging, qualification, and rollback.

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
committed.

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
