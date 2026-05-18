# ADR-036: Snapshot Endpoint Registry Boundary

## Status

accepted

## Date

2026-05-18

## Context

`src/aptl/core/snapshot.py` builds `RangeSnapshot.services` and
`RangeSnapshot.ssh` from running containers, but it currently duplicates
host-facing ports, labels, users, and Wazuh credentials in local maps. The
same host-port facts are owned by Docker Compose and are already visible to
snapshot capture through `ContainerSnapshot.ports`, populated by
`DeploymentBackend.host_list_lab_containers` per ADR-023.

The change requested by issue #261 is architectural, not just mechanical:
deduplicating endpoint metadata must not accidentally create a second source of
truth for Docker Compose port mappings, runtime secrets, API terminal routing,
or first-party configuration.

Relevant incumbents:

- `src/aptl/core/deployment/backend.py` and ADR-023 own host inventory through
  typed backend methods, including container port mappings.
- `src/aptl/core/snapshot.py` owns the snapshot DTO and redacts it at
  `RangeSnapshot.to_dict()`.
- `docker-compose.yml` owns host-published ports and container target ports.
- `src/aptl/core/config.py` and ADR-025 own strict durable first-party config.
- `src/aptl/core/env.py`, `src/aptl/core/credentials.py`, ADR-028, and ADR-029
  own runtime secret binding, generated secret-bearing config, and redaction.
- `src/aptl/api/routers/terminal.py` owns the WebSocket terminal allow-list and
  live SSH connection policy.

## Decision

Snapshot endpoint metadata may be centralized in a small registry, but that
registry is an annotation table, not a deployment authority. It may define
stable display metadata and protocol expectations such as:

- container name
- endpoint display name
- endpoint kind (`service` or `ssh`)
- protocol
- expected container target port
- SSH username, where SSH access is intentionally exposed
- optional default credential display string only for existing designed lab
  credentials that are already redacted at snapshot serialization boundaries

Host-facing published ports must be derived from the runtime
`ContainerSnapshot.ports` data returned by the deployment backend. The registry
must not carry host-published port numbers that duplicate Docker Compose. When a
running registered container has no matching published port, snapshot capture
should omit that endpoint or represent it as unavailable; it must not fall back
to a stale hardcoded host port.

Credentials remain out of scope for endpoint deduplication. Issue #261 may move
the existing snapshot credential literals into the endpoint registry only to
avoid local duplication in `snapshot.py`, but it must not redesign credential
storage, move `.env` secrets into `aptl.json`, expose generated config, or make
the endpoint registry a secret-management layer. Any credential-shaped value in
snapshot output remains subject to ADR-029 redaction through
`RangeSnapshot.to_dict()`.

The endpoint registry should live in Python core code near snapshot/control
plane consumers, not in `aptl.json`, until there is a runtime user-owned
configuration need. Adding it to `AptlConfig` would invoke ADR-025's strict
schema and migration expectations and would incorrectly turn fixed lab topology
annotations into user configuration.

## Security Layers

- **Deployment inventory gate:** published host ports come from
  `DeploymentBackend.host_list_lab_containers`; snapshot logic consumes the
  backend-normalized `ContainerSnapshot.ports` shape instead of invoking Docker
  or parsing Compose files itself.
- **Runtime-state validation:** endpoint construction must match a registered
  container plus expected target port/protocol against `ContainerSnapshot.ports`.
  Missing, malformed, or non-matching port entries are treated as unavailable
  endpoint data, not as validation exceptions that fail the whole snapshot.
- **Serialization and error envelopes:** `RangeSnapshot.to_dict()` remains the
  redaction boundary. Logs, CLI JSON, API responses, output files, and future
  run archives must not bypass it or print unredacted credentials from registry
  entries.
- **Secret-handling surface:** `.env`, generated service config, private keys,
  API tokens, and runtime service secrets continue to use ADR-028 and ADR-029.
  Endpoint metadata must not read generated config files or embed private
  material to make snapshots more convenient.
- **OS/process exposure:** endpoint derivation should be pure Python over
  already-captured backend data. It should not add subprocess calls, process
  argv secrets, or Docker/SSH command execution.
- **API terminal auth surface:** WebSocket origin checks, container allow-list
  validation, and live SSH connection behavior stay in
  `src/aptl/api/routers/terminal.py`. A snapshot registry must not weaken or
  replace that enforcement path.

## Extensibility

The extensibility seam is the registry entry's expected container target port,
not the host-published port. A future service should be addable by registering
its container name, display metadata, endpoint kind, protocol, and target port;
changing the host-published port should require only a Docker Compose change
because snapshots derive the host side from runtime inventory.

If a future deployment backend exposes richer structured port data, adapt the
backend-to-`ContainerSnapshot` normalization first so all snapshot consumers see
one shape. Do not add a Compose-file parser or backend-specific branches inside
endpoint construction.

## Non-Goals

- Do not redesign credential ownership or remove the existing snapshot
  credential field as part of endpoint-map deduplication.
- Do not move endpoint metadata into `aptl.json` without a separate
  user-configurability decision.
- Do not make the endpoint registry authoritative for Docker Compose port
  publishing, container health, lab readiness, or WebSocket terminal access.
- Do not parse `docker-compose.yml` during snapshot capture.
- Do not add a new validation framework, exception hierarchy, persistence
  schema, or redaction helper for endpoint construction.

## Anti-Patterns

- Hardcoding host-published ports in a new registry under a different name.
- Treating container target ports and host-published ports as interchangeable.
- Reading generated secret-bearing config to populate snapshot endpoint fields.
- Bypassing `DeploymentBackend` with raw Docker commands from endpoint helpers.
- Duplicating the API terminal allow-list in a way that implies snapshot display
  metadata authorizes shell access.
- Adding caller-owned registry overrides before a real configuration contract
  exists.
