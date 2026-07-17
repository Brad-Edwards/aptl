# RNG-003 Range Checkpoint/Restore Preflight

This note is the architecture preflight for RNG-003 / issue #453. It is
guidance, not an implementation plan. Existing ADRs remain binding: ADR-013,
ADR-023, and ADR-037 own deployment backends; ADR-025 owns first-party config;
ADR-029 owns secret handling; ADR-030 owns lab lifecycle result envelopes;
ADR-031 owns orchestration guards; ADR-036 owns the inventory snapshot endpoint
registry; ADR-039 owns web control-plane authentication; ADR-043 owns named
volume seeding; ADR-044 owns ACES-aligned run records; and ADR-045 owns lifecycle
policy execution.

## Architecture Decisions

- Use **range checkpoint** for restorable state. Keep the existing names and
  contracts distinct:

  - `RangeSnapshot` is redacted, read-only inventory evidence.
  - ACES `RuntimeSnapshot` is portable logical runtime/provenance state.
  - A range checkpoint is privileged, byte-preserving backend state plus a
    versioned manifest. Neither existing snapshot schema can be extended into
    this role without concept and security leakage.

- The Docker Compose baseline is a **cold, crash-consistent restore point**:
  container writable layers, Docker-managed volumes, and project-owned network
  definitions/attachments are captured behind one range-wide quiescence
  barrier. Restore recreates storage and topology, then cold-starts processes.
  It does not promise process-memory resume, live TCP/UDP session resume,
  conntrack/NAT table restoration, or byte-identical Docker object IDs.
- Docker's CRIU-backed checkpoint feature must not be the baseline. Docker
  documents it as experimental, single-host-focused, and subject to runtime and
  terminal limitations. A future process-resume consistency mode may use it
  only after an explicit backend capability probe and separate compatibility
  tests; it must not silently replace the portable cold-restore mode.
- All Docker and Compose access belongs on `DeploymentBackend` as narrow typed
  checkpoint operations. Extend the incumbent backend and runner boundary; do
  not add raw Docker calls in CLI, API, runstore, snapshot, ACES, or validation
  code, and do not add a generic Docker argv passthrough.
- Range ownership is the configured deployment project and its labels:
  project directory, backend identity, and `DeploymentConfig.project_name`.
  Capture and restore must use Compose project labels and the existing
  realization-network label, not `aptl-*` name prefixes or daemon-wide
  enumeration. Runtime objects created by Docker-socket consumers such as
  Shuffle or Cortex are in scope only when they carry an explicit range-owner
  label. Unlabelled daemon-global workers must be reported as an unsupported
  completeness gap, never guessed into the range.
- The checkpoint manifest is the only new schema the feature needs. It is a
  small, versioned envelope containing checkpoint/source/parent identity,
  backend and platform compatibility facts, consistency mode, capture state,
  payload references with sizes and cryptographic digests, project-owned
  container/volume/network inventory, external bind-mount dependencies, and
  optional references to the canonical ACES runtime snapshot and run record.
  It must reference, not copy or locally mirror, `RangeSnapshot`, ACES
  `RuntimeSnapshot`, workflow, participant, evaluation, or run-record schemas.
- Opaque payloads belong under the ignored, project-contained
  `.aptl/checkpoints/` state tree, not in `LocalRunStore`, `runs/`, normal run
  exports, `exporter.py`, or a user-selected arbitrary path. A redacted metadata
  reference may be written into the active run so lineage is auditable without
  copying checkpoint bytes into the run archive.
- A checkpoint is published atomically: payloads are staged under an incomplete
  owner-only directory, checksummed, and the complete manifest is published
  last. An incomplete or checksum-invalid capture is never listable as
  restorable. Restore verifies the full manifest, compatibility gates, source
  dependencies, and every payload digest before making a destructive change.
- Restore is not clean boot and not normal startup. It may reuse config/env
  validation, backend resolution, health/readiness probes, inventory capture,
  diagnostics, and run-record reference patterns, but it must not rerun
  credential hydration, generated-config rendering, Suricata volume seeding,
  SOC seed scripts, or ACES provisioning after payload restoration. Those
  startup steps mutate the state RNG-003 is meant to recover.
- Branching never rewinds or overwrites the original run archive. A restore
  starts a new run/trace lineage and records the source run and parent
  checkpoint. Reusing a prior `trace_id`, run id, WebSocket/session token, or
  append-only evidence path would corrupt provenance and create replayable
  identity leakage.
- One project-scoped operation lock must serialize start, stop, kill, lifecycle
  enforcement, checkpoint, and restore. Promote the incumbent
  `lifecycle_enforce._single_owner_lock` pattern into the shared range-operation
  boundary instead of adding a checkpoint-only lock. The current no-op Windows
  fallback is insufficient for destructive restore; unsupported locking must
  fail closed.

## Consistency And Completeness Contract

- "Arbitrary point" means an operator-selected, admitted checkpoint boundary,
  not an arbitrary CPU instruction. Stop admitting new participant, workflow,
  terminal, and lifecycle mutations; wait for or reject in-flight control-plane
  operations; then freeze all owned data-plane writers before the first payload
  is read.
- The first supported consistency mode is `crash-consistent`. Every owned
  container must be frozen as one range before writable layers or shared
  volumes are captured, and all must be resumed in a `finally`-equivalent path.
  Failure to freeze every writer is a failed checkpoint, not a degraded
  checkpoint.
- Container writable layers and mounted volumes are separate payload classes.
  Docker documents that `docker container commit` excludes mounted-volume data,
  so a committed image alone can never satisfy RNG-003. Runtime `Mounts`
  inventory, not only top-level Compose YAML, is the authority for volume/bind
  classification.
- Docker-managed named and anonymous volumes preserve file bytes plus the
  metadata required by the local driver: ownership, modes, symlinks, hardlinks,
  timestamps, ACLs/xattrs where the platform supports them, driver identity,
  and mount destination. Unsupported volume drivers fail capability admission;
  they are not silently treated as local tar archives.
- Host bind mounts, the Docker socket, `/sys/fs/cgroup`, checked-in source,
  `.env`, keys, generated config, and generated certificates are external host
  dependencies, not Docker-managed checkpoint payloads. The manifest records
  their resolved classification and safe digest/identity facts. Restore must
  reject drift that affects the recovered containers and must never overwrite
  source-owned or operator-secret host files. This makes the initial boundary a
  same-project recovery/replay feature, not host-disaster recovery.
- Network state means project-owned network policy and topology: driver,
  internal/egress flag, IPAM subnet/gateway, labels, container attachments,
  static IPs, aliases, and backend-realized networks. It does not mean packets
  in flight, sockets, conntrack/NAT/firewall kernel tables, DNS cache, or
  external network services. If RNG-003's acceptance criteria use "complete
  network state" to include live connections, the stable Docker Compose
  baseline is insufficient and the requirement must remain unverified until a
  process/network checkpoint capability is admitted and tested.
- ACES logical state must use the installed ACES contract and validator:
  `RuntimeSnapshot`, `RuntimeSnapshotEnvelopeModel`, and, when a live control
  plane owns the scenario, its `ControlPlaneStore`/`LocalControlPlaneStore`.
  Do not serialize a second APTL runtime snapshot or treat the start-time copy in
  the REP-001 record as live checkpoint state.

## Canonical Incumbents To Reuse

- Deployment and ownership: `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, `_subprocess_kwargs()`, `_run()`, project-label filters,
  `_COMPOSE_PROJECT_LABEL`, `_REALIZATION_NETWORK_LABEL`,
  `BackendTimeoutError`, `LabResult`, and `LabStatus`.
- Lifecycle and concurrency: `orchestrate_lab_start()`, `stop_lab()`,
  `clean_boot_lab()`, `_LAB_START_STEPS`, `_single_owner_lock()`,
  `StartupOutcome`, `StartupDiagnostic`, and `_emit_diagnostic()`.
- Config and environment: `AptlConfig`, `DeploymentConfig`,
  `RunStorageConfig`, `load_config()`, `load_dotenv()`, `EnvVars`,
  `env_vars_from_dict()`, `find_placeholder_env_values()`, and strict Pydantic
  `extra="forbid"` behavior. Invocation-time checkpoint choices do not belong in
  `aptl.json` unless a durable runtime consumer exists.
- State, identity, and lineage: `ScenarioSession`,
  `resolve_active_run_dir()`, trace-context generation, ADR-044's run-record
  composition, ACES `RuntimeSnapshotEnvelopeModel`, and ACES
  `LocalControlPlaneStore`. Preserve canonical payloads and references; do not
  mirror them in checkpoint DTOs.
- Inventory and network truth: `capture_snapshot()`, `RangeSnapshot.to_dict()`,
  `container_networks()`, `host_list_lab_containers()`,
  `host_list_lab_networks()`, `host_inspect_network()`, and the realization
  network helpers. `RangeSnapshot` remains post-restore evidence, not the
  restore recipe.
- Persistence and path safety: `_validate_id()` and relative-path containment
  from `runstore.py`, plus the owner-only directory, same-directory temporary
  file, `os.replace()`, and symlink-containment patterns in `credentials.py`,
  `_soc_ca_io.py`, `host_keys.py`, and `env.py`. Promote a shared primitive if
  checkpoint code needs it; do not copy a near-equivalent validator.
- Security and observability: `redact()`, `get_logger()`, ADR-029's artifact
  classification, `LocalRunStore.write_json()` for redacted lineage metadata,
  and existing narrow diagnostics. `write_file()`/`copy_file()` and
  `exporter.py` are not safe checkpoint payload boundaries.
- CLI/API boundaries: `_confirm_destructive()`, `resolve_config_for_cli()`,
  Typer exit conventions, `verify_token`, `WebAuthSettings`, BFF/CSRF gates,
  `LabActionResponse`, and API Pydantic projection style.

## Security And Validation Layers

| Layer | Checkpoint/restore requirement |
| --- | --- |
| Auth surface | The initial surface should remain host CLI/core. Any later HTTP trigger must stay behind ADR-039 `verify_token` plus BFF/CSRF enforcement and accept a validated checkpoint id, never an arbitrary path, Docker argument list, upload body, or payload URL. A Compose-hosted API must not pause itself; an out-of-band controller or an explicit control-plane exclusion is required. |
| Destructive-action gate | Restore uses the existing destructive confirmation convention and a project-scoped operation lock. Verify source integrity and compatibility before confirmation/destruction. A failed restore must retain the source checkpoint and enough narrow evidence for recovery; an in-place restore is not falsely described as atomic. |
| Config shape | Durable non-secret knobs use strict `AptlConfig`; transient consistency mode, checkpoint id, and restore intent use typed boundary values with closed sets and bounded lengths. Do not add unchecked dicts, stringly cleanup modes, or a second profile/project schema. |
| Env/secret binding | Normal startup still owns `.env` parsing, `EnvVars`, placeholder rejection, and generated config. Checkpoint code must not parse or print `.env` values. External secret-bearing bind inputs are digest-checked dependencies, not normal payload metadata. |
| Range ownership | Every container, volume, and network is admitted by project/realization labels and expected mount relationships. Objects from another Compose project or unlabelled daemon-global workers are rejected or explicitly reported; names and prefixes are not authorization. |
| Backend/remote transport | All capture/restore I/O flows through typed backend methods and the shared runner so SSH `DOCKER_HOST`, project scoping, timeout translation, and local/remote identity stay aligned. Large payloads stream to bounded files; they are not buffered in `CompletedProcess`, interpolated into shell strings, or assumed to exist at the same path on an SSH daemon. |
| Payload path | Resolve generated checkpoint ids under `.aptl/checkpoints`; reject absolute paths, `..`, symlink escapes, hard-link tricks, and pre-existing non-directory targets. Stage with owner-only permissions and atomic publish. Never extract an archive into the project root or host filesystem. |
| Payload confidentiality | Byte-preserving layers and volumes can contain passwords, tokens, private material, databases, and target evidence, so redaction is impossible. Apply ADR-029's privileged-checkpoint amendment: `0700` directories, `0600` files on POSIX, no stdout/API/OTel/run-export exposure, no registry push, and authenticated encryption before any explicit off-host copy. Metadata still passes through `redact()`. |
| Archive integrity | Use a versioned manifest and cryptographic digest/size for every payload. Validate the manifest shape and all digests before mutation; reject duplicate names, unknown required payload kinds, unsupported format versions/drivers/platforms, and archive entries that could escape the target volume. |
| OS/process exposure | Preserve argv-list subprocess construction. Payload bytes, keys, `.env` values, container environment, database contents, private keys, and auth material must not enter argv, environment added solely for the operation, process titles, log messages, exceptions, or temp filenames. Checkpoint identifiers and image tags are identifiers, not auth credentials. |
| Error envelope | Backend timeouts remain `BackendTimeoutError`; core/CLI/API failures use existing `LabResult`, diagnostics, and Typer/FastAPI projections. If an artifact receipt needs a checkpoint id and state, keep it a narrow value carrier; do not create a parallel lifecycle taxonomy or broad exception hierarchy. Raw Docker/Compose/tar/CRIU stderr never crosses the boundary. |
| Observability | Record checkpoint id, parent/source run ids, phase name, object counts, byte counts, durations, consistency mode, and narrow outcome labels. Do not log full Docker inspect payloads, container environments, mount contents, archive member data, raw commands, or backend stderr. |
| Post-restore gate | Capture a new redacted `RangeSnapshot`, verify project-owned containers/volumes/networks and readiness through existing probes, and validate any restored ACES envelope through its canonical contract model. A cold process restart and expected new Docker ids are not mismatches; missing data/topology or contract-invalid logical state is a failed restore. |

## Reliability Guardrails

- Estimate payload size and free space before freezing the range. Capture and
  restore timeouts must be based on measured bytes with generous margins and
  progress reporting, not the 15-second host-inventory or 600-second seed
  constants. Large Wazuh, TheHive, OpenSearch, Tempo, and capture volumes can
  make a range-wide pause long enough to affect clients and health checks.
- Resume every successfully paused container on capture failure. Record and
  surface an unpause failure as a readiness/capability failure; do not leave a
  partially frozen lab while reporting only that the checkpoint failed.
- Verify the source checkpoint before stopping the current lab. Because Docker
  local volumes cannot be atomically renamed into place, in-place restore needs
  an explicit recovery policy, such as a verified safety checkpoint of the
  current state or a clearly acknowledged no-rollback mode. Never imply that a
  sequence of volume deletes/imports is transactional.
- Preserve seed/restored-state ordering. `seed_named_volumes()`, Suricata
  seeding, SOC scripts, credential hydration, and ACES provisioning are correct
  for a new range but corrupt a restored one. Readiness and inventory may run
  afterward; initialization may not.
- Treat capture-sidecars and append-only run evidence separately from range
  rollback. Restoring a data-plane checkpoint must not truncate MCP/Kali/SOC
  evidence already written after the checkpoint; a branch gets new evidence
  paths with a parent reference.
- Do not claim deterministic replay from state restore alone. Current REP-001
  explicitly records that scenario seeds are absent, and wall-clock time,
  randomness, host kernel scheduling, external services, and user/agent input
  remain uncontrolled. RNG-003 supplies a repeatable starting state; strict
  deterministic outcomes require separate time, seed, and external-input
  controls.

## Extensibility Seam

The seam is the existing `DeploymentBackend` checkpoint capability plus one
versioned checkpoint manifest. It is parameterized by:

- range identity: project directory, backend/provider identity, and
  `deployment.project_name`;
- consistency mode: first `crash-consistent`, later optional
  `application-consistent` hooks or explicitly experimental process resume;
- payload codec/format version per artifact kind, without exposing raw Docker
  commands to callers;
- restore target identity, which initially must match the same project/backend
  and can later support an explicitly named branch instance without relying on
  container prefixes;
- parent checkpoint/source run identity for lineage; and
- external bind dependency policy, so a future encrypted host-disaster backup
  can include selected generated state without changing the container/volume
  manifest contract.

Do not preemptively add a second deployment service, storage-provider Protocol,
repository layer, schema registry, or cloud exporter. A future remote encrypted
checkpoint store can consume complete local manifests and payload streams when
there is a real second storage implementation.

## Whole-Repo Surface

- `aptl.json`, `DeploymentConfig.project_name`, `RunStorageConfig`, `.env`,
  `.env.example`, scenario selection, and ACES lock/runtime contracts.
- `docker-compose.yml`: all service profiles, project labels, static networks,
  top-level named volumes, bind mounts, Docker socket mounts, generated config,
  and the Suricata seed volumes.
- Dynamic backend state: ACES realization networks/attachments, Docker-socket
  worker containers, anonymous volumes, committed writable layers, image
  architecture/digests, volume drivers, and daemon OS/storage-driver identity.
- Project state: `.aptl/checkpoints/`, `.aptl/config/`, `.aptl/lifecycle/`,
  `.aptl/session.json`, `.aptl/trace-context.json`, `.aptl/runs/`, configured
  `runs/`, `keys/`, generated SOC/indexer certs, and `.mcp.json`.
- Python boundaries: `src/aptl/core/deployment/`, `lab.py`, `lab_types.py`,
  `snapshot.py`, `runstore.py`, `exporter.py`, `session.py`, `telemetry.py`,
  `lifecycle_enforce.py`, `credentials.py`, and ACES adapter/repro modules.
- User surfaces: `src/aptl/cli/lab.py`, `src/aptl/cli/_common.py`, and, only if
  later exposed, `src/aptl/api/main.py`, `deps.py`, `routers/lab.py`,
  `schemas.py`, plus mirrored web types.
- Host/runtime layers: local Docker Engine or Docker Desktop VM, SSH Docker
  transport, filesystem permissions and free space, process argv/temp files,
  kernel/network state, local volume driver semantics, and shared-daemon tenant
  boundaries.
- Workflow gates: `.ground-control.yaml`, `.gc/plan-rules.md`, `pytest`,
  `pre-commit run --all-files`, and a dedicated live Docker round-trip that
  mutates a writable layer, a named volume, and network attachment before and
  after checkpoint/restore. Mock-only tests cannot verify RNG-003.

## Gotchas And Anti-Patterns

- Adding restorable bytes to `RangeSnapshot`, ACES `RuntimeSnapshot`, the
  endpoint registry, run-record JSON, or normal run exports.
- Calling a metadata-only `aptl lab status --json` output a checkpoint, or
  treating Docker image tags/config hashes as restorable state.
- Committing container filesystems without separately capturing volumes.
- Capturing volumes sequentially while writers continue, or pausing one
  container at a time while shared databases/queues remain active.
- Using normal startup/clean-boot seeding after restore and overwriting the
  recovered state.
- Capturing every daemon object, every `aptl-*` name, the Docker socket, host
  bind sources, or another Compose project's objects.
- Assuming a local checkpoint path is visible to an SSH-remote Docker daemon,
  or silently snapshotting the local daemon for an `ssh-compose` project.
- Buffering multi-gigabyte image/volume payloads in memory or raw subprocess
  results.
- Extracting tampered tar members onto the host, trusting filenames inside a
  payload, or publishing the manifest before payload verification completes.
- Logging/persisting raw inspect data, image environment, database/archive
  content, Docker stderr, or secret-bearing command text.
- Restoring old run/trace/session identifiers and appending new branch evidence
  to the original run.
- Calling topology restore "complete network restore" when live connections,
  conntrack, firewall state, or external services are not preserved.
- Calling a restored starting state "deterministic replay" without controlling
  time, randomness, scheduling, external input, and scenario seeds.
- Relying on the current POSIX-only lifecycle lock while Windows falls through
  unlocked, or creating a second checkpoint lock that races start/stop/kill.

## Non-Goals And Initial Boundaries

- Do not implement RNG-003 in this preflight.
- Do not rename or expand the existing `RangeSnapshot` or ACES
  `RuntimeSnapshot` contracts.
- Do not guarantee process-memory resume, open connection resume, packet/
  conntrack/NAT/firewall kernel state, live migration, or byte-identical Docker
  ids in the cold-restore baseline.
- Do not provide host-disaster recovery, cross-architecture migration,
  cross-volume-driver migration, registry push, S3 export, or unencrypted
  off-host checkpoint transport in the initial boundary.
- Do not overwrite `.env`, keys, checked-in config, generated host config/certs,
  run archives, or ACES inventory evidence during restore.
- Do not add web/API checkpoint upload/download or browser-held checkpoint
  secrets in the initial surface.
- Do not add automatic checkpoint retention/garbage collection before quota,
  lineage, incomplete-capture, and restore-safety semantics are explicit.
- Do not redesign Docker Compose, ACES SDL, endpoint metadata, SOC collectors,
  run archive layout, web authentication, or lifecycle policy evaluation.

## References

- [Docker container commit](https://docs.docker.com/reference/cli/docker/container/commit/)
- [Docker volume backup and restore](https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes)
- [Docker checkpoint/restore](https://docs.docker.com/reference/cli/docker/checkpoint/)
