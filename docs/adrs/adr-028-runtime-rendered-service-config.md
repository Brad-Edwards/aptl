# ADR-028: Runtime-Rendered Service Config

## Status

accepted

## Date

2026-05-10

## Context

Issue #200 changes the ownership model for service configuration at lab
startup. Today, Wazuh credential synchronization rewrites checked-in files
under `config/` during `aptl lab start`. That makes a git checkout mutable at
runtime, hides the difference between source templates and generated artifacts,
and makes reproducibility checks harder.

This supersedes ADR-007's older "Project-Rooted Credential Writes" guardrail
only for the part that allows startup to write credentialized values back into
checked-in `config/` files. ADR-007 remains authoritative for the Python CLI
control-plane shape.

Relevant incumbents already exist:

- `src/aptl/core/env.py` owns `.env` parsing, required-secret validation, and
  placeholder rejection through `find_placeholder_env_values`.
- `src/aptl/core/config.py` and ADR-025 own the strict `aptl.json` schema.
- `src/aptl/core/lab.py` owns lab-start step ordering through
  `_LabStartContext` and `_LAB_START_STEPS`.
- `src/aptl/core/credentials.py` owns Wazuh config credential rendering today,
  including XML/YAML escaping and project-root containment checks.
- `src/aptl/core/deployment/` owns Docker Compose execution through the
  `DeploymentBackend` abstraction from ADR-013 and ADR-023.
- `src/aptl/utils/redaction.py` and ADR-012 own serialization-boundary
  redaction for snapshots, telemetry, and exported artifacts.
- `src/aptl/services/misp_suricata_sync/rule_writer.py` is the existing
  idempotent atomic-file-write helper pattern for generated runtime artifacts.

## Decision

Checked-in files under `config/` are source-owned baselines or templates.
Startup must not mutate them in place to inject runtime credentials or other
generated runtime state.

Credentialized service configuration and generated runtime artifacts must be
rendered or seeded to a dedicated generated output location, preferably under
the ignored project state tree (`.aptl/`), or from an explicit template asset
into that output location. Containers that need the generated file should
consume the generated artifact via the existing Docker Compose ownership path,
with read-only mounts where the service supports them.

Rendering APIs must keep the existing boundary shape: accept the project root
and canonical project-relative inputs, construct known paths internally, resolve
symlinks, and reject paths that escape their allowed root before any I/O. The
same rule applies to generated output paths. Do not add arbitrary caller-owned
file targets.

Secret-bearing generated directories must be created with restrictive
permissions (`0700` directories), written atomically, and left out of version
control. The generated *files* default to `0600`, but when a file is
bind-mounted into a container whose process may run under a UID that does not
match the host UID that ran `aptl lab start` (for example the Wazuh Dashboard image's
non-root user), the file is widened to `0644` so the container can read it—the
owner-only parent directory remains the host-side access control, and the file
still never reaches the repo because `.aptl/` is gitignored. Logging and
returned errors may include artifact labels and paths, but must not include
secret values.

### Concrete realization (issue #200)

The first two files brought under this model are the Wazuh credentialized
configs:

| Checked-in template (source, never written) | Rendered output (ignored, `0644` under a `0700` dir) | Compose mount |
| --- | --- | --- |
| `config/wazuh_dashboard/wazuh.yml` | `.aptl/config/wazuh_dashboard/wazuh.yml` | `wazuh.dashboard` → `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` |
| `config/wazuh_cluster/wazuh_manager.conf` | `.aptl/config/wazuh_cluster/wazuh_manager.conf` | `wazuh.manager` → `/wazuh-config-mount/etc/ossec.conf` |

`core.credentials.sync_dashboard_config` / `sync_manager_config` read the
template, apply the credential substitution, and write the result under
`.aptl/config/` (the existing ignored state tree, alongside `session.json` and
the red-team capture file) with `0700` directories, an atomic rename, and a
`0644` file mode (so the Wazuh Dashboard's non-root process can read its
bind-mounted config). The renderer also rejects a zero-match substitution and
any symlink in the `.aptl/config/...` path chain (escape *or* back into a
tracked file). `core.lab._step_sync_credentials` runs before
`_step_check_bind_mounts` and `_step_start_containers`, so the rendered files
exist by the time Docker Compose binds them, and a render failure aborts lab
start rather than leaving a stale copy in place. `aptl lab start` is the
supported entrypoint; a bare `docker compose up` against a fresh checkout will
not find the rendered mounts—the same property the gitignored
`config/wazuh_indexer_ssl_certs/*` certificate mounts already have, so the
manual / CI deployment docs route through `aptl lab start`. The other ~18
`config/wazuh_cluster/*` mounts (rules, decoders, certs, helper scripts) are not
credentialized and stay on `config/`.

### Concrete realization (issue #287)

The MISP-driven Suricata rule writer is non-credentialed, but it still produces
runtime state. Its checked-in files under `config/suricata/rules/misp/` are
source-owned baselines only:

| Checked-in baseline (source, never written) | Generated output (ignored) | Compose mount |
| --- | --- | --- |
| `config/suricata/rules/misp/misp-iocs.rules` | `.aptl/suricata/rules/misp/misp-iocs.rules` | `suricata` / `misp-suricata-sync` → `/var/lib/suricata/rules/misp/misp-iocs.rules` |
| `config/suricata/rules/misp/misp-md5.list` | `.aptl/suricata/rules/misp/misp-md5.list` | `suricata` / `misp-suricata-sync` → `/var/lib/suricata/rules/misp/misp-md5.list` |
| `config/suricata/rules/misp/misp-sha1.list` | `.aptl/suricata/rules/misp/misp-sha1.list` | `suricata` / `misp-suricata-sync` → `/var/lib/suricata/rules/misp/misp-sha1.list` |
| `config/suricata/rules/misp/misp-sha256.list` | `.aptl/suricata/rules/misp/misp-sha256.list` | `suricata` / `misp-suricata-sync` → `/var/lib/suricata/rules/misp/misp-sha256.list` |

`aptl lab start` seeds those baselines into `.aptl/suricata/rules/misp/` before
bind-mount validation and container startup. Suricata mounts the generated
directory read-write because its image entrypoint chowns the rules tree before
starting; `misp-suricata-sync` mounts the same generated directory read-write
and continues to write `RULES_OUT_PATH=/var/lib/suricata/rules/misp/misp-iocs.rules`.
The writable target is generated state under `.aptl/`, not checked-in `config/`.
The in-container path remains under Suricata's `default-rule-path`, so
`misp/misp-iocs.rules` and the hash-list sidecars keep resolving through
Suricata's normal relative-path lookup while a lab start no longer dirties
checked-in `config/`.

## Guardrails

- Reuse `load_dotenv`, `env_vars_from_dict`, `EnvVars`, and
  `find_placeholder_env_values` for every value rendered from `.env`.
- Reuse `AptlConfig` if a new runtime-config output knob is needed; do not add
  unvalidated ad hoc environment parsing unless it follows the strict parser
  pattern used by `misp_suricata_sync.config`.
- Keep lab-start orchestration in `core.lab` as a flat sequence of
  `_step_*` functions returning `LabResult | None`.
- Preserve `PathContainmentError` semantics for security-boundary failures:
  containment breaches fail startup; ordinary render misses can remain warnings
  only when the current service contract intentionally tolerates them. Generated
  bind-mount sources required for container startup must fail startup if they
  cannot be rendered or seeded.
- Route Docker Compose behavior through `DeploymentBackend`; do not shell out
  from a new helper when an existing backend method owns that concern.
- Keep generated config out of snapshots and run archives unless it is redacted
  or represented only by hashes and metadata.

## Security Layers

- **Environment binding:** `.env` is parsed by `load_dotenv`, shaped by
  `EnvVars`, and placeholder-checked before rendering. Missing required secrets
  fail before any generated file is written.
- **First-party config shape:** new durable knobs belong in `AptlConfig` with
  `extra="forbid"` so typos fail during `aptl config validate` and startup.
- **Filesystem containment:** source templates and generated outputs are
  resolved and checked with `Path.resolve()` plus `is_relative_to()` before
  reads, writes, chmods, or mount references.
- **Secret handling at rest:** generated files live in an ignored state/output
  tree with restrictive permissions and atomic replacement.
- **OS/process exposure:** secrets must not be passed in command-line argv,
  compose entrypoint strings, or log text. Existing container environment
  variables are acceptable only where the service already consumes them that way.
- **Error envelopes:** `LabResult`, CLI output, API responses, and logs may name
  the failed artifact or validation layer, but not the secret value.
- **Serialization boundaries:** snapshot/status/export paths continue to use
  `redact()` and must not add unredacted generated config content.

## Extensibility

The seam is the generated-artifact root plus per-service relative output names.
One future service should be addable by registering another template/source and
generated relative path, not by hardcoding a second one-off writer or changing
the source `config/` ownership model again.

## Non-Goals

- Do not redesign the whole Docker Compose layout.
- Do not introduce a new configuration schema parallel to `AptlConfig` and
  `EnvVars`.
- Do not change Wazuh credential semantics beyond where the credentialized
  files are rendered and mounted.
- Do not redesign unrelated generated-artifact semantics while moving them out
  of checked-in `config/`.
- Do not archive or display generated secret-bearing config as a debugging aid.

## Anti-Patterns

- Mutating checked-in files under `config/` during `aptl lab start`.
- Treating source config, templates, generated files, and persisted runtime
  state as the same concept.
- Copying the existing regex replacement into another module instead of
  reusing or replacing the current credential-rendering boundary.
- Adding a caller-provided output path without containment checks.
- Passing secrets through process argv, compose command strings, or exception
  messages.
