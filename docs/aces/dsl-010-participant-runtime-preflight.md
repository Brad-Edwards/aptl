# DSL-010 Participant Runtime Preflight

!!! warning "Historical backend-profile milestone"
    This is a dated preflight record, kept as written. Its description of the
    promotion from `orchestration-evaluation` records the profile transition at
    that milestone. APTL's current claim is `full-remote-control-plane`; see the
    current [backend manifest](techvault-static-validation-gate.md#backend-manifest).

This note is the architecture preflight for DSL-010 / issue #554. It is
guidance, not an implementation plan. ADR-035 remains the binding ACES adoption
decision, and the existing DSL-008/live-gate notes remain the topology and live
proof guardrails. This note narrows the participant/runtime action surface that
promotes APTL from an `orchestration-evaluation` backend to a
`participant_runtime` capable reference emulation backend.

## Architecture Decisions

- `ParticipantRuntime` is a fourth ACES backend component on the existing
  APTL `RuntimeTarget`, beside `AptlProvisioner`, `AptlOrchestrator`, and
  `AptlEvaluator`. It must not be hidden inside provisioning, workflow driving,
  evaluator registration, CLI code, or live-gate proof code.
- The backend manifest promotion is all-or-nothing: `create_aptl_manifest()`
  must add `ParticipantRuntimeCapabilities`, the same `RuntimeTarget` must pass
  a participant runtime instance, and `run_target_conformance()` plus the
  published `aces conformance backend` CLI must pass the promoted profile with
  no `conformance.unsupported-capability-claim` diagnostics.
- APTL consumes the published ACES participant contracts as-is. Episode state
  must use `ParticipantEpisodeExecutionState`; episode history must use
  `ParticipantEpisodeHistoryEvent`; behavior/action proof must populate
  `RuntimeSnapshot.participant_behavior_history` with the published participant
  behavior event shape. Do not create APTL-local participant DTOs or schemas.
- The control-plane path under proof is the ACES control plane:
  `RuntimeControlPlane.initialize_participant_episode()`,
  `reset_participant_episode()`, `restart_participant_episode()`, and
  `terminate_participant_episode()`. Direct adapter calls may be unit-tested,
  but the live proof must assert `operation-receipt-v1`,
  `operation-status-v1`, `runtime-snapshot-v1`, and realization provenance
  through the control plane.
- The real action proof must operate against realized containers through
  `DeploymentBackend.container_exec()` and post-action `capture_snapshot()`.
  The proof cannot be in-memory state only, a fake command result, or a
  contract-surface-only state transition.
- The first action surface should be deliberately small and truthful. If the
  proof drives Kali as a red participant, claim only the participant roles,
  behavior features, and interaction features whose required contracts are
  actually emitted and validator-clean. Do not claim blue, green, white, or
  multi-party interaction semantics unless a real proof exists for them.
- Live-action evidence belongs beside the curated live-proof artifacts and may
  reuse their result/snapshot shape, but it should carry the added participant
  operation id, episode state, behavior history, action result, and snapshot /
  realization-provenance references. It should not become a new run archive
  schema.

## Cross-Cutting Concerns To Reuse

- ACES authorities: `aces_backend_protocols.protocols.ParticipantRuntime`,
  `ParticipantEpisodeInitializeRequest`, `ParticipantEpisodeResetRequest`,
  `ParticipantEpisodeRestartRequest`, `ParticipantEpisodeTerminateRequest`,
  `ParticipantRuntimeCapabilities`,
  `PARTICIPANT_RUNTIME_CAPABILITY_REQUIRED_CONTRACTS`,
  `RuntimeControlPlane`, `ApplyResult`, `RuntimeSnapshot`,
  `OperationReceipt`, `OperationStatus`, `Diagnostic`,
  `iter_participant_episode_snapshot_violations()`, and
  `iter_participant_behavior_snapshot_violations()`.
- Existing APTL adapter seams: `create_aptl_runtime_target()`,
  `create_aptl_manifest()`, `AptlProvisioner`, `AptlOrchestrator`,
  `AptlEvaluator`, `interpret_provisioning_plan()`, `select_backend_profiles()`,
  `AptlRealization.details()`, and `render_aces_diagnostics()`.
- Deployment and inventory owners: `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, `ComposeQueryMixin`, project-name scoping,
  compose-project label filters, bounded `container_exec()`,
  `capture_snapshot()`, `RangeSnapshot.to_dict()`,
  `list_container_snapshots()`, and `container_networks()`.
- Live proof owners: `aptl.validation.curated_live_proof`,
  `ExpectedMatrix`, `compare_to_snapshot()`, `summarize_snapshot()`,
  the curated live-proof driver under
  `docs/aces/techvault-curated-live-validation-gate/`, and the full live-gate
  `LiveGateCheck` / `LiveGateReport` failure category convention.
- Config, env, and generated artifact owners: strict `AptlConfig`,
  `ContainerSettings.enabled_profiles()`, `DeploymentConfig`, `load_config()`,
  `load_dotenv()`, `env_vars_from_dict()`, `find_placeholder_env_values()`,
  generated Wazuh/Dashboard config, SOC TLS generation, Suricata named-volume
  seeding, and bind-mount validation.
- Persistence, logging, and redaction owners: `LocalRunStore.write_json()` /
  `write_jsonl()` / `append_jsonl()`, `aptl.utils.redaction.redact()`,
  `RangeSnapshot.to_dict()`, `aptl.utils.logging.get_logger()`, `curl_safe`,
  ADR-023, ADR-029, ADR-030, ADR-031, ADR-036, ADR-037, ADR-039, and ADR-040.
- Repo gates: `pytest`, `pre-commit run --all-files`, manual
  `aces-scenario-gate`, live-gate integration marker, `.gc/plan-rules.md`, and
  Conventional Commit PR titles (release-please drives releases).

## Security And Validation Layers

- **ACES component shape:** `RuntimeTarget` validates manifest/component
  presence and method call shapes. A manifest with `participant_runtime` and no
  component, or a component with missing `initialize` / `reset` / `restart` /
  `terminate` / `status` / `results` / `history`, must fail construction.
- **Manifest and conformance:** `ParticipantRuntimeCapabilities` validates
  controlled vocabulary values, and
  `PARTICIPANT_RUNTIME_CAPABILITY_REQUIRED_CONTRACTS` dictates the participant
  episode and behavior contracts that must be added to
  `supported_contract_versions`. The implementation should let
  `run_target_conformance()` and `aces conformance backend` reject overclaims.
- **Episode and behavior envelopes:** participant state/history must be created
  through the ACES dataclasses or validated with the ACES snapshot violation
  iterators. Do not hand-build loosely shaped dicts without contract validation.
- **Config shape:** durable non-secret knobs stay in `AptlConfig`. Do not add an
  unchecked `aptl.json` participant-action block or TechVault-only preset table.
  If the action needs a tunable, make it a narrow typed parameter with a safe
  default at the adapter/proof boundary.
- **Environment binding:** `.env` remains parsed and placeholder-checked before
  startup. Participant diagnostics may name env variable names or missing
  prerequisites, but never env values.
- **Deployment and OS exposure:** all container action execution goes through
  `DeploymentBackend.container_exec()` with argv-list commands and bounded
  timeouts. Do not pass passwords, API tokens, cookies, private keys, or
  generated config values in process argv, shell strings, logs, or diagnostics.
- **Container/project isolation:** action target resolution must be derived from
  ACES realization details and the project-scoped backend/snapshot. Do not
  address unscoped Docker names on a shared daemon or use a host-level Docker
  escape hatch.
- **Snapshot and provenance:** successful action proof must update participant
  episode/behavior snapshot fields and tie the action to realized container
  evidence in `runtime-snapshot-v1` and realization provenance. A successful
  command exit code alone is not enough.
- **Error envelopes:** ACES-facing failures are `Diagnostic` records and
  `operation-status-v1`. APTL-facing failures remain `LabResult`,
  `StartupDiagnostic`, `LiveGateCheck`, or pytest assertions. Every message
  crossing logs, CLI/API output, telemetry, or persistence must be redacted.
- **Persistence:** structured live-action artifacts use the existing redacting
  JSON/JSONL write boundaries or the curated proof's redacted snapshot summary.
  Opaque file copies are inappropriate unless the artifact is explicitly
  classified as reviewed target evidence.

## Extensibility Seam

The seam is `(participant_address, participant_role, episode_id,
action_descriptor, target_container, command_argv, timeout, selected_profiles,
realization_details, operation_id)`. The action descriptor should be data about
the intended participant operation, not a branch on `techvault`, scenario path,
or Compose profile name.

The next reasonable change is another participant role or action against a
different realized node. That should require adding a new validated action
descriptor and evidence assertion, not editing the manifest generator, the
control-plane plumbing, or a TechVault-specific conditional. Multi-agent
coordination belongs to AGT-001 / AGT-002 and should consume this seam rather
than widening it now.

## Gotchas And Anti-Patterns

- Claiming `participant_runtime` in the manifest before the `RuntimeTarget`
  actually provides the component.
- Adding participant contracts to `supported_contract_versions` without
  emitting the corresponding episode and behavior snapshot fields.
- Treating `initialize` / `reset` / `restart` / `terminate` as lab
  start/stop aliases. They are participant episode transitions, not Compose
  lifecycle operations.
- Recording an action in memory without driving a realized container.
- Calling raw `docker exec`, `docker inspect`, `docker logs`, `docker compose`,
  or `curl` from participant runtime or proof code.
- Creating a new participant schema, validation layer, exception hierarchy,
  readiness taxonomy, redaction helper, manifest shim, or run evidence schema.
- Dispatching on scenario name, file path, catalog id, `techvault`, or profile
  preset instead of participant address, realization details, and snapshot data.
- Overclaiming participant roles or behavior/interaction features to satisfy
  profile shape while the proof only exercises a single emulated action.
- Letting generated config, SOC tokens, `.env` values, cookies, private keys,
  or API tokens leak into action history, command strings, diagnostics, proof
  JSON, committed evidence, or logs.
- Using `--skip-seed` for the live-action proof. DSL-010 explicitly needs a
  boot without `--skip-seed` so seeded runtime behavior is part of the proof.

## Non-Goals

- Do not implement DSL-010 in this preflight.
- Do not add new ACES schemas, profiles, or controlled vocabulary terms.
- Do not redesign `RuntimeControlPlane`, `RuntimeTarget`, `DeploymentBackend`,
  Docker Compose topology, startup ordering, generated config, SOC TLS,
  endpoint registry, web auth, terminal relay, or run archive layout.
- Do not make participant actions a general shell-execution API.
- Do not add multi-agent coordination, scheduling, contention, or negotiation
  semantics; those belong to AGT-001 / AGT-002.
- Do not change the public default scenario or replace the full TechVault live
  gate. The live-action proof is an additional participant-runtime proof layer.
