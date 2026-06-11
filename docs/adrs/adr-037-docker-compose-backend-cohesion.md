# ADR-037: Docker Compose Backend Cohesion

## Status

accepted

## Date

2026-05-18

## Context

Issue #262 asks whether `DockerComposeBackend` should be split after
ADR-023 grew the `DeploymentBackend` surface from lifecycle-only into
lifecycle, host inventory, and container interaction. The class is now
large, but the methods still share one operational boundary: one Docker
daemon reached through the Docker CLI, with local and SSH transports
sharing the same runner, timeout, parse, logging, and project-scoping
rules.

The existing architecture already names the three responsibilities in
`DeploymentBackend` and routes callers through typed methods rather than
raw Docker argv passthroughs. The security-sensitive behavior is not the
sectioning itself; it is the shared execution boundary:

- `_subprocess_kwargs`, `_run`, and `_run_streaming` centralize cwd,
  capture/streaming semantics, timeout translation, and SSH `DOCKER_HOST`
  environment injection.
- `container_exists`, `container_list`, `host_list_lab_containers`, and
  `host_list_lab_networks` enforce compose-project scoping for shared
  Docker daemons.
- `BackendTimeoutError`, `LabResult`, and `LabStatus` are the existing
  error/result surfaces. Splitting must not create a second exception
  hierarchy or response DTO.
- ADR-029 redaction rules apply before subprocess output crosses logs,
  CLI/API/web responses, snapshots, run archives, or telemetry.

## Decision

Do not split `DockerComposeBackend` into lifecycle / host-inventory /
container-operation mixins for issue #262, and do not replace the class
with module-level delegation solely to reduce file length.

Keep one concrete Docker Compose backend class that implements the
existing `DeploymentBackend` Protocol. The Protocol comments remain the
public responsibility boundary; the backend class may keep matching
method-group comments and private pure helpers for parsing or decision
tables.

The extensibility seam is the runner boundary, not a mixin hierarchy:
future Docker-CLI transports should reuse or override the smallest
runner hook that carries cwd/env/capture/streaming/timeout behavior.
Today that hook is `_subprocess_kwargs`, with `_run` and
`_run_streaming` preserving the backend-defined timeout exception.

## Guardrails

- Keep all Docker/Compose access for lifecycle, host inventory, and
  container interaction behind `DeploymentBackend`; do not add raw Docker
  subprocess calls in CLI, API, snapshot, continuity, flags, or
  collector callers.
- Keep host inventory typed. Do not add a generic `host_run(args)`,
  `docker(args)`, or command-passthrough escape hatch.
- Preserve argv-list subprocess construction. Do not concatenate
  user-supplied container names, shell paths, timestamps, profiles, or
  image names into shell strings.
- Preserve project scoping via the configured compose project name and
  `com.docker.compose.project` labels anywhere host/container inventory
  can observe a shared daemon.
- Preserve bounded calls for daemon-wide probes and timeout translation
  to `BackendTimeoutError`.
- Preserve existing result and error envelopes: `LabResult`,
  `LabStatus`, `BackendTimeoutError`, CLI `typer.Exit`, and API schemas.
- Keep parsing helpers private unless another module has a real caller.
  Do not promote Docker CLI output rows into new public DTOs just to
  support a split.

## Consequences

### Positive

- Avoids a multiple-inheritance design whose only user-visible effect
  would be more files and a more fragile method-resolution contract.
- Keeps SSH-local parity tied to one runner path, which is the part that
  actually protects remote deployments.
- Reduces the risk of duplicating project-label filtering, timeout
  policy, subprocess kwargs, logging behavior, or JSON/TSV parsing.

### Negative

- `DockerComposeBackend` remains a large concrete class.
- Future substantial behavior growth may still require extraction, but
  that extraction should be driven by duplicated logic or a second real
  transport/provider, not by method count alone.

### Risks

- A future implementation could reintroduce raw Docker calls outside the
  backend because host inventory feels "daemon-level." ADR-023 and this
  ADR reject that: host inventory is still a typed backend responsibility.
- A future split could accidentally remove project-label filters and leak
  other tenants' containers or networks on shared SSH daemons.
- A future helper layer could log raw stderr/stdout or full command
  strings containing secrets, violating ADR-029.

## Non-Goals

- Do not redesign `DeploymentBackend`.
- Do not add lifecycle / host-inventory / container-operation Protocols.
- Do not introduce mixins, strategy objects, services, repositories,
  DTOs, or exception hierarchies for this issue.
- Do not change Docker Compose commands, CLI/API behavior, startup
  ordering, snapshot schemas, run archive shapes, or SSH configuration.
- Do not solve future Kubernetes, Podman, or Nomad provider design here.

## Anti-Patterns

- Splitting code by public method group while each group still reaches
  into the same private runner state.
- Using mixins whose methods depend on undocumented attributes such as
  `_project_dir`, `_project_name`, `_run`, or `_run_streaming`.
- Replacing named backend methods with generic argv passthroughs.
- Duplicating label filters, env construction, JSON/NDJSON parsing, TSV
  parsing, shell fallback logic, timeout constants, or logging policies.
- Treating `SSHComposeBackend` as a separate semantic provider that needs
  duplicate lifecycle/container/host methods; it is a Docker Compose
  transport variation.

## References

- [ADR-013](adr-013-deployment-abstraction.md): deployment backend
  abstraction.
- [ADR-023](adr-023-container-interaction-in-deployment-backend.md): typed container interaction and host inventory on the backend.
- [ADR-029](adr-029-control-plane-secret-handling.md): redaction and
  secret-handling boundaries.
- [ADR-031](adr-031-lab-orchestration-contract-guards.md): lab
  orchestration contract guardrails.
- [Issue #262](https://github.com/Brad-Edwards/aptl/issues/262).
