# ADR-013: Deployment Backend Abstraction Layer

## Status

accepted

## Date

2026-03-22

## Context

From v2.0 onward, all lab lifecycle operations (start, stop, status, kill) were implemented as direct subprocess calls to `docker compose` in `lab.py` and `kill.py`. This coupling was appropriate when APTL ran exclusively on a single developer machine ([ADR-001](adr-001-docker-compose-deployment.md)), but it prevents deploying the lab to:

- A dedicated lab server (classroom or team deployments)
- Cloud VMs (EC2, GCE, Azure VM)
- Container orchestration platforms (Kubernetes, Nomad)
- Hybrid environments (some services local, some remote)

The coupling was isolated to the **deployment lifecycle** — scenario definitions already reference containers by name (not Docker-specific concepts), and MCP servers use config-driven `docker-lab-config.json` files. This meant a deployment abstraction could be introduced without touching scenario or MCP code.

### Alternatives Considered

1. **Kubernetes-first**: Replace Docker Compose entirely with Kubernetes manifests. Over-engineered for the current scale (5-19 containers). Adds operational complexity without clear benefit for single-user labs.

2. **Terraform provider**: Use Terraform to manage Docker Compose and cloud deployments. Heavy dependency, slow feedback loop, and the lab doesn't need infrastructure-as-code semantics.

3. **Ansible playbooks**: SSH-based deployment automation. Good for multi-host but introduces a new tool dependency and doesn't integrate with the Python CLI.

4. **Protocol-based abstraction with multiple backends**: Define a Python Protocol for deployment operations and implement concrete backends for each target. Follows the existing `RunStorageBackend` pattern in `runstore.py`.

## Decision

Introduce a `DeploymentBackend` Protocol in `src/aptl/core/deployment/` with two initial implementations:

### Protocol

```python
class DeploymentBackend(Protocol):
    def start(self, profiles: list[str], *, build: bool = True) -> LabResult: ...
    def stop(self, profiles: list[str], *, remove_volumes: bool = False) -> LabResult: ...
    def status(self) -> LabStatus: ...
    def kill(self, profiles: list[str]) -> tuple[bool, str]: ...
    def pull_images(self, images: list[str]) -> list[str]: ...
```

### Backends

| Backend | Provider Key | Description |
|---------|-------------|-------------|
| `DockerComposeBackend` | `docker-compose` | Local Docker Compose (default). Wraps the existing subprocess logic from `lab.py` and `kill.py`. |
| `SSHComposeBackend` | `ssh-compose` | Remote Docker Compose over SSH. Sets `DOCKER_HOST=ssh://user@host` so all Docker CLI commands execute against a remote daemon. |

### Configuration

Backend selection is driven by `aptl.json`:

```json
{
  "deployment": {
    "provider": "docker-compose"
  }
}
```

For SSH remote deployment:

```json
{
  "deployment": {
    "provider": "ssh-compose",
    "ssh_host": "lab-server.example.com",
    "ssh_user": "labadmin",
    "ssh_key": "~/.ssh/lab_key",
    "ssh_port": 22,
    "remote_dir": "/opt/aptl"
  }
}
```

A factory function `get_backend(config, project_dir)` instantiates the correct backend.

### Scope

This abstraction covers **deployment lifecycle** only: start, stop, status, kill, and image pulling. Container interaction (exec, logs, inspect) used by `snapshot.py`, `flags.py`, and `collectors.py` remains Docker-specific — those operations are a separate concern that can be abstracted independently when needed.

### Backward Compatibility

The public functions `start_lab()`, `stop_lab()`, `lab_status()`, and `kill_lab_containers()` retain their existing signatures with an additional optional `backend` parameter. When no backend is provided, they default to `DockerComposeBackend`, preserving identical behavior for all existing callers (CLI, API, tests).

## Consequences

### Positive

- **Multi-host deployment**: Labs can run on remote servers via SSH without changing scenario definitions or MCP configurations
- **Extensible**: New backends (Kubernetes, Podman, cloud-specific) can be added by implementing the Protocol without modifying core orchestration
- **Testable**: The Protocol enables mock backends for unit testing without Docker
- **Follows existing patterns**: Same Protocol + concrete implementation + factory approach as `RunStorageBackend`
- **No breaking changes**: All existing code continues to work via default backend

### Negative

- **Additional indirection**: Deployment operations now go through a Protocol interface instead of direct subprocess calls. The indirection is one level deep and adds negligible overhead.
- **SSH backend limitations**: The `DOCKER_HOST=ssh://` approach requires the local Docker CLI version to be compatible with the remote Docker daemon. Mismatched versions can cause subtle failures.
- **Partial abstraction**: Container interaction (exec, logs) is not yet abstracted. Remote deployments that need flag collection or snapshot capture still require direct SSH access to containers.

### Risks

- The SSH backend has not been tested against all Docker versions. The `DOCKER_HOST=ssh://` feature was introduced in Docker 18.09 and has edge cases around context handling and compose file paths.
- Future backends (Kubernetes) may need a richer Protocol interface — e.g., namespace management, resource quotas, or pod scheduling constraints that don't map cleanly to the current `profiles` concept.
