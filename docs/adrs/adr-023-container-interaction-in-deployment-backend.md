# ADR-023: Container Interaction in the Deployment Backend Protocol

## Status

accepted

## Date

2026-05-03

## Context

[ADR-013](adr-013-deployment-abstraction.md) introduced the
`DeploymentBackend` Protocol covering lab lifecycle operations — `start`,
`stop`, `status`, `kill`, `pull_images` — and explicitly listed container
interaction (`exec`, `logs`, `inspect`) as out of scope, noting it could be
"abstracted independently when needed." That moment arrived with
[issue #138](https://github.com/Brad-Edwards/aptl/issues/138), which adds
three CLI commands required by [CLI-004](../../../.gc/) — `aptl container
list`, `aptl container shell`, `aptl container logs` — and ships them
alongside the long-stubbed `aptl config show`/`aptl config validate`.

The CLI commands need a single uniform path that works against both the
local `DockerComposeBackend` and the SSH-remote `SSHComposeBackend`. The
SSH backend already centralises `DOCKER_HOST=ssh://` env injection inside
its `_run` override, so any container-interaction methods added to the
Protocol pick up SSH-aware execution for free; the alternative — letting
the CLI shell out to raw `docker compose` itself — would route around the
backend entirely and silently break SSH-remote deployments.

Three core helpers were already issuing raw `docker exec` / `docker
inspect` calls outside the backend: `core/snapshot.py` (`docker exec` ×4
plus `docker inspect <name>`), `core/flags.py` (`docker exec <c> cat`), and
`core/collectors.py` (`docker exec aptl-suricata cat …` plus `docker logs
<name> --since/--until`). Leaving those untouched while adding new
backend methods would have left the very duplication this Protocol is
meant to eliminate.

### Alternatives considered

1. **Sibling Protocol** (`ContainerBackend`) decoupled from
   `DeploymentBackend`. Cleaner separation of concerns, but every caller
   (CLI, snapshot, flags, collectors) would have to instantiate and thread
   *two* backends and ensure they target the same Docker daemon. Buys
   nothing in practice — the SSH-remote case explicitly requires the same
   transport for both. Rejected.
2. **Generic `run_docker(args)` method** instead of named methods. Smaller
   surface area but loses callsite intent ("inspect this container" vs
   "run an arbitrary docker command"), makes mocking harder, and invites
   future callers to bypass the typed methods. Rejected.
3. **Use `docker compose exec/logs` for everything** (compose-flavored).
   Works for `container_list` (project-scoped enumeration), but the
   remaining commands take container names — which is what
   `container_list` shows the user. Forcing service names everywhere
   would be inconsistent. Rejected for `logs`/`shell`/`exec`/`inspect`;
   accepted for `list`.

## Decision

Extend the existing `DeploymentBackend` Protocol with **six**
container-interaction methods. Both `DockerComposeBackend` and
`SSHComposeBackend` implement them; the SSH backend reuses its existing
env-injection pattern (and gains a parallel `_run_streaming` override for
the non-captured cases).

```python
class DeploymentBackend(Protocol):
    # … existing lifecycle methods …

    def container_list(
        self, *, all_containers: bool = True
    ) -> list[dict]: ...

    def container_logs(
        self, name: str, *, follow: bool = False, tail: int | None = None
    ) -> int: ...

    def container_logs_capture(
        self, name: str, *,
        since: str | None = None,
        until: str | None = None,
    ) -> subprocess.CompletedProcess: ...

    def container_shell(
        self, name: str, *, shell: str | None = None
    ) -> int: ...

    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> subprocess.CompletedProcess: ...

    def container_inspect(self, name: str) -> dict: ...
```

Implementation rules:

- `container_list` uses `docker compose ps -a --format json` because
  enumeration is naturally project-scoped. Output is parsed as either a
  JSON array or NDJSON, matching `status()` behaviour.
- `container_logs`/`container_logs_capture`/`container_shell`/
  `container_exec`/`container_inspect` use raw `docker <op> <container>`
  because they all take container names — the names users see in
  `container_list` output. `DOCKER_HOST=ssh://…` is honoured uniformly by
  both `docker` and `docker compose` CLIs, so SSH-remote works without
  per-method special handling.
- `container_shell` with `shell=None` tries `/bin/bash` first and falls
  back to `/bin/sh` if bash exits with 126 or 127 (command-not-executable
  / not-found). An explicit `--shell` skips the fallback. This keeps the
  default ergonomic for the lab's bash-heavy containers without breaking
  on alpine-based images.
- Streaming methods (`container_logs`, `container_shell`) inherit the
  parent's stdin/stdout/stderr — no capture — so the user sees logs
  arrive live and shells get a real TTY. A new `_run_streaming` helper
  alongside `_run` keeps env construction in one place.
- `container_exec` is non-interactive and captured (one-shot commands).
  `container_logs_capture` is the captured variant of `container_logs`
  for programmatic consumers (collectors).
- `container_inspect` returns the first element of `docker inspect`'s
  JSON array as a plain dict, with `{}` on any failure.

The three previously-raw callers (`core/snapshot.py`, `core/flags.py`,
`core/collectors.py`) are updated to take a `backend` parameter and route
container `exec`/`inspect`/`logs` through the Protocol. Truly host-level
calls (`docker version`, `docker compose version`, `docker ps -a --filter
name=aptl-` for project-wide enumeration, `docker network ls/inspect`)
remain raw subprocess calls — they target the daemon itself, not specific
containers, and don't fit the Protocol's container-interaction model.

## Consequences

### Positive

- **CLI symmetry**: `aptl container list/shell/logs` behaves identically
  on local Docker Compose and SSH-remote labs. No special-case code in
  the CLI layer.
- **SSH-remote correctness for snapshots, flags, and run-archive
  collectors**: previously these would have silently targeted the local
  Docker daemon even when the lab was running on a remote host. They now
  route through the same backend the rest of the CLI uses.
- **Single env-injection point**: `_run` and `_run_streaming` each
  construct the env exactly once. Adding a future backend (Kubernetes,
  Podman) requires implementing those two helpers.
- **Testability**: All three refactored callers can now be exercised with
  a `MagicMock()` backend instead of `subprocess` patching. Tests stop
  caring about argv shape and focus on behaviour.
- **Eliminates raw `docker exec`/`docker inspect` from
  `core/`** (host-level `docker version` / `docker network` calls
  intentionally remain).

### Negative

- **Protocol grew from 5 to 11 methods.** Adding a new backend now
  involves implementing six more methods. Mitigated by inheritance:
  `SSHComposeBackend` overrides only the two `_run*` helpers and
  inherits the rest from `DockerComposeBackend`.
- **Two log methods (`container_logs` / `container_logs_capture`).**
  Streaming and captured semantics genuinely differ; collapsing them
  into a single method would have required either a `capture` flag with
  a union return type or a buffer-and-return approach that defeats
  streaming's purpose.

### Risks

- **`docker compose ps -a` schema drift.** If Docker Compose changes the
  field names emitted by `--format json`, `container_list` consumers
  (the CLI table renderer) will silently lose columns. Same risk as
  `status()` had pre-CLI-004; out of scope to address here.
- **`/bin/bash` → `/bin/sh` fallback shells too eagerly.** If a user
  intends bash but it's missing, they'll land in sh instead of getting
  a clear error. Acceptable: sh is functional and the user can rerun
  with `--shell /bin/bash` to see the explicit failure.

## References

- [ADR-013](adr-013-deployment-abstraction.md) — original deployment
  abstraction; this ADR supersedes its "out of scope" clause for the
  six listed methods.
- [Issue #138](https://github.com/Brad-Edwards/aptl/issues/138) — the
  CLI work that drove this Protocol extension.
- CLI-002, CLI-004, CLI-007 in Ground Control.
