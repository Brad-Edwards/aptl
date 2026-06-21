# ADR-043: Suricata Runtime Config Ownership Boundary

## Status

accepted

## Date

2026-06-20

## Context

Issue #325 closes an ownership regression in the Suricata lab service. The
upstream `jasonish/suricata:7.0` image entrypoint chowns Suricata config and
rule paths to the image's `suricata` user. In the image that UID is `991`; on
Ubuntu hosts the same numeric UID commonly belongs to `systemd-network`. When
Suricata sees host bind mounts at those paths, the in-container chown rewrites
host-side ownership. The affected paths are:

- checked-in source config:
  - `config/suricata/suricata.yaml`
  - `config/suricata/rules/local.rules`
- generated runtime rules:
  - `.aptl/suricata/rules/misp/`

Making the checked-in binds read-only is not a valid fix. The upstream
entrypoint runs under `set -e`; a failed chown exits the container and leaves
Suricata crash-looping.

Existing decisions constrain the repair:

- ADR-019 keeps Suricata IDS-only. This issue must not alter detection versus
  prevention semantics.
- ADR-022 owns MISP-driven Suricata rule semantics: alert-only translation,
  stable SIDs, hash sidecar files, idempotent writes, and unix-command reload.
- ADR-028 owns the source-owned versus generated-artifact boundary. Checked-in
  `config/` files are inputs, not runtime mutation targets.
- ADR-031 owns lab-start orchestration: a flat sequence of `_step_*`
  functions returning `LabResult | None`, with narrow secret-safe contract
  failures.
- ADR-037 owns Docker access through `DeploymentBackend`; new Docker behavior
  must not become a generic argv passthrough.

This ADR supersedes only the Suricata concrete realization in ADR-028 and the
host-bind wording in ADR-022. Their rule semantics and source-owned
configuration boundary remain authoritative.

## Decision

Choose the named-volume plus entrypoint-wrapper design.

Suricata must no longer bind-mount checked-in `config/suricata/...` files, or
the generated `.aptl/suricata/rules/misp/` tree, onto paths the upstream
entrypoint chowns.

At lab start, APTL materializes Suricata runtime inputs into Docker
project-scoped named volumes:

- a config seed volume sourced from `config/suricata/`;
- a MISP rule volume seeded from `config/suricata/rules/misp/` and shared
  read-write by `suricata` and `misp-suricata-sync`.

The Suricata service mounts the config seed volume at a non-upstream path and
uses a small wrapper entrypoint. The wrapper copies the seeded config into the
image-owned `/etc/suricata/` tree, then `exec`s the upstream image entrypoint
with the original command arguments. The upstream entrypoint may still chown
`/etc/suricata/...` and `/var/lib/suricata/rules/misp`, but those are now the
container writable layer and Docker-managed named volumes, not host source
files.

The internal Suricata paths stay stable:

- `/etc/suricata/suricata.yaml`
- `/etc/suricata/rules/local.rules`
- `default-rule-path: /var/lib/suricata/rules`
- `misp/misp-iocs.rules` plus `misp-*.list` sidecars

The MISP sync service keeps writing `RULES_OUT_PATH` under
`/var/lib/suricata/rules/misp/` and keeps using the existing unix-command
socket reload path. Do not merge operator-authored `local.rules` and
MISP-generated rules.

The implementation must also retire the legacy host bind directory
`.aptl/suricata/rules/misp/`. Prior lab runs may already have left it owned by
UID 991, so lab start may need a narrow Docker-root cleanup or repair for that
legacy path. That cleanup is compatibility debt only: after this ADR, the path
is not a Suricata runtime source. It must be path-contained, reject symlinked
chains, and target only the canonical legacy project-relative path.

Do not set explicit global Docker volume names. Compose project scoping must
continue to derive names from the configured compose project, so multiple
worktrees and custom `deployment.project_name` values do not collide.

## Rejected Options

### Image-side copy via `command`

Rejected. Compose `command:` is passed to the upstream entrypoint; it does not
run before the entrypoint's chown. Using `command:` either leaves the chown trap
in place or bypasses the upstream entrypoint entirely, which creates a second
Suricata startup contract.

### Rendered `.aptl/suricata/config/` bind mount plus recurring root cleanup

Rejected as the primary design. It keeps the host bind mount under a path the
Suricata image chowns, then relies on a privileged cleanup before every
subsequent start. That repairs the symptom but preserves the host ownership
hazard and makes idempotency depend on Docker-root deletion of host paths.

Narrow legacy cleanup is allowed only to recover from pre-ADR-043 `.aptl/`
ownership damage and to make that retired path manageable again.

## Guardrails

- Keep source config, runtime seed data, Docker named volumes, and persisted
  service state as separate concepts.
- Keep Suricata startup under `aptl lab start`; a bare `docker compose up`
  against a fresh checkout is not required to materialize seed volumes.
- Place any seed orchestration in the existing lab-start sequence before
  `_step_check_bind_mounts` and `_step_start_containers`; seed failures are
  fatal `LabResult` failures because Suricata would otherwise start with stale
  or absent config.
- Reuse or extract the existing containment and no-symlink-chain checks from
  `src/aptl/core/credentials.py`; do not add weaker path checks.
- Reuse `PathContainmentError`, `CredentialRenderError` where applicable,
  `LabResult`, and the existing redacted logging/diagnostic surfaces. Do not
  add a Suricata-specific exception hierarchy or result DTO.
- Route Docker behavior through a narrow backend-owned operation if code must
  invoke a seed container. Do not add `docker(args)`, `host_run(args)`, or any
  generic passthrough to `DeploymentBackend`.
- Preserve argv-list subprocess construction. Do not concatenate project paths,
  volume names, service names, or shell fragments into unvalidated shell
  strings.
- Preserve `misp-suricata-sync`'s existing `ServiceConfig`, `rule_writer`, IOC
  validation, alert-only translator, and reload retry behavior.
- If new durable knobs are needed, add them to strict `AptlConfig`. Do not
  introduce ad hoc environment variables or a second config schema for
  Suricata seeding.
- Keep the wrapper script data-free. It may name fixed container paths, but it
  must not carry `.env` values, API keys, certificates, or operator secrets.
- Regression coverage must pin first-run seeding, repeated-start idempotency,
  a prior UID-991-owned legacy `.aptl/suricata/rules/misp/` tree, and unchanged
  host ownership for the checked-in Suricata source files.

## Security Layers

- **Environment binding:** this design adds no new secret-bearing environment
  values. Existing MISP and Wazuh secrets still flow through `load_dotenv`,
  `EnvVars`, `find_placeholder_env_values`, and the MISP sync service's
  `ServiceConfig.from_env()`.
- **First-party config shape:** durable operator controls stay in
  `AptlConfig` with `extra="forbid"`. The default path should need no new
  operator config.
- **Filesystem containment:** source reads are limited to canonical
  project-relative paths under `config/suricata/`. Legacy `.aptl` cleanup is
  limited to the canonical retired path and must reject symlinked path
  components before Docker-root cleanup runs.
- **Docker boundary:** named volumes are Compose project-scoped and reached
  through the deployment backend's runner semantics. Shared daemon behavior
  must preserve ADR-037 project scoping.
- **Container runtime boundary:** Suricata's upstream entrypoint remains the
  authority for the image's normal startup. The wrapper only stages config into
  the image-owned path before delegating.
- **OS/process exposure:** seed operations and wrapper invocation must pass
  non-secret fixed paths and volume names via argv-list commands. No secrets
  may appear in process argv, Compose command strings, wrapper text, or logs.
- **Error envelopes:** failures return existing `LabResult` errors naming the
  artifact or validation layer. Raw Docker stderr and exception text must be
  redacted before crossing logs, CLI, API, web, telemetry, or run archives.
- **Serialization boundaries:** snapshots, status output, and exports must not
  add generated config or named-volume contents as unredacted artifacts.

## Maintainability

Canonical incumbents the implementation must build on:

- `src/aptl/core/lab.py` for lab-start sequencing and fatal/non-fatal result
  behavior.
- `src/aptl/core/credentials.py` for path containment, generated artifact
  errors, mode enforcement precedent, and Suricata baseline constants.
- `src/aptl/core/deployment/` for Docker Compose execution and project
  scoping.
- `docker-compose.yml` for Suricata, `misp-suricata-sync`, and named-volume
  wiring.
- `src/aptl/services/misp_suricata_sync/` for IOC translation, idempotent
  rule writes, and reload behavior.
- `tests/test_lab.py` and `tests/test_credentials.py` for orchestration and
  seed/ownership regression coverage.

Do not duplicate the MISP sync schema, the Suricata rule writer, the lab
result envelope, the Docker backend runner, or the config/env validators.

## Extensibility

The seam is a typed named-volume seed specification:

- canonical project-relative source path;
- Compose project-scoped volume name;
- destination subpath inside the volume;
- whether the volume is seed-only or shared read-write at runtime;
- optional canonical legacy host path to repair or retire.

One future generated-volume service should be addable by registering another
seed spec and reusing the same backend-owned materialization path, not by
adding another one-off Docker cleanup or another generated-artifact schema.

## Whole-Repo Surface

This decision touches:

- `docker-compose.yml` service mounts, entrypoint, and top-level volumes;
- `src/aptl/core/lab.py` startup ordering and failure envelopes;
- `src/aptl/core/credentials.py` or a small extracted helper for canonical
  Suricata seed paths and containment;
- `src/aptl/core/deployment/` if seed containers require backend support;
- `containers/misp-suricata-sync/Dockerfile` comments that currently describe
  a host bind mount;
- `config/suricata/suricata.yaml` path invariants;
- `tests/test_lab.py`, `tests/test_credentials.py`, and compose/inventory
  assertions that inspect Suricata mounts.

## Non-Goals

- Do not build or maintain a custom Suricata image.
- Do not upgrade or replace `jasonish/suricata:7.0` as part of this issue.
- Do not redesign Suricata detection, MISP IOC semantics, Wazuh active
  response, or SOC seeding.
- Do not change Wazuh credential rendering or the broader ADR-028 generated
  config model.
- Do not solve general remote generated-artifact materialization unless the
  deployment backend implements it explicitly. Refusing SSH-remote startup with
  the existing ADR-028 shape remains acceptable.

## Anti-Patterns

- Read-only binding checked-in Suricata files directly into `/etc/suricata`.
- Binding `.aptl/suricata/...` to a path the Suricata image chowns and relying
  on recurring root cleanup as the steady-state design.
- Using `command:` to try to run setup before the upstream entrypoint.
- Adding broad `rm -rf` helpers, shell-string Docker commands, or generic
  Docker passthroughs.
- Setting explicit unscoped Docker volume names.
- Rewriting `suricata.yaml` internal paths to match a host workaround.
- Merging `local.rules` with MISP-generated rules.
- Duplicating env/config validation, exception hierarchies, logging policy, or
  MISP rule-writing logic for this issue.
