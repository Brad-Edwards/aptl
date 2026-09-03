# Issue 939 Fail-Closed Kali Capture Session Admission Preflight

This note fixes the architecture boundary for issue #939. It is design
guidance, not an implementation plan. It narrows and amends ADR-041 and
ADR-042 for sessions governed by an admitted required-capture binding; it does
not replace EXP-010's admission, collector, evidence, or persistence contracts.
OpenRAE/env-packs#282 remains the owner of the TechVault wrapper/client bytes,
and OpenRAE/rae#1112 remains the owner of portable capture-manifest semantics.

## Architecture Decisions And Guardrails

### One admitted binding, then one bounded session authority

- Required Kali session capture must be matched by the existing code-owned
  collector registry and pinned as an immutable `CaptureBinding` in the trial
  plan before any range mutation. The registration declaration, backend
  observation manifest, runtime collector, and session-admission protocol must
  describe the same capability and version. Do not infer support from a Kali
  node, wrapper digest, container, socket, README, or successful `ping`.
- The runtime session grant is a narrow use of the pinned binding, not another
  capture policy or DTO. Its authority is bounded to the exact attempt/run ID,
  session ID, capture-spec and requirement identity, registration and
  implementation version, effective-config digest, audience/runtime epoch,
  protocol version, issue time, expiry, and unique nonce. It grants permission
  to start that capture session only; it grants no shell, SSH, Docker, file,
  collector-selection, or evidence-persistence authority.
- Trusted composition code may expose a session-issuance operation from the
  admitted Kali collector to the host-side SSH/MCP owner. `aptlShellEnv`, an
  SSH private key, `AcceptEnv`, the ForceCommand wrapper, and the participant
  process are transports or consumers, never issuers. No binding means no
  proof; a mismatched or changed binding is not re-matched at runtime.
- Keep issuance and participant data on different authority surfaces. A
  control-plane-only channel provisions bounded, expiring one-use state to the
  verifier; the workload-reachable session channel can only consume it and
  append/finalize that accepted session. The workload must not reach an API
  that mints, widens, refreshes, lists, revokes, or introspects grants.
- Atomic consumption is part of authentication. Verification and the unused to
  consumed transition occur under one lock/transaction before
  `session_accepted`; concurrent or later reuse returns the same stable replay
  class. Replay state must either survive for the proof lifetime or be made
  obsolete by a verifier runtime-epoch/key rotation on restart.

Portable representation of authored capture requirements remains RAES-owned.
APTL must not create a TechVault-only capture manifest while waiting for
OpenRAE/rae#1112. A backend-private runtime projection may carry the already
admitted binding to the issuer, but it cannot invent or weaken the authored
requirement that admission consumes.

### Synchronous admission and exactly once execution

The correctness ordering is strict:

1. Validate the RAES artifacts, match every required capture, persist the
   immutable plan, and bind an attempt/run.
2. Start every required collector and prove the session-admission prerequisites.
3. Issue one bounded proof for the exact run/session/binding and establish the
   authenticated capture connection.
4. Atomically validate and consume the proof, initialize every required sink,
   and return a versioned `session_accepted` acknowledgement bound to the same
   run/session/audience.
5. Only then start `SSH_ORIGINAL_COMMAND` or the interactive shell, exactly once.
6. Latch the real command outcome, finalize capture once, and separately record
   finalization and evidence completeness.

Missing, malformed, expired, replayed, wrong-audience, wrong-runtime-epoch,
run/session-mismatched, binding-mismatched, protocol-incompatible, or
unacknowledged grants reject before step 5. After step 5, capture interruption
or finalization failure invalidates or makes evidence partial through the
existing `CollectorStatus` / `AcquisitionDisposition` path; it never erases the
latched command outcome and never retries the command. Capture admission,
command outcome, capture finalization, evidence completeness, and archive seal
state remain five separate facts.

The EXP-010 coordinator must enforce all-required startup, not merely
`bool(started)`. Its current shape can run `trial_body` when one collector
started even though another binding resolved to `SOURCE_UNAVAILABLE`; a Kali
session admission must not inherit that partial-start behavior.

### Endpoint identity and private proof handling

- The current abstract socket plus `SO_PEERCRED` is not endpoint authentication:
  it is workload-reachable, a Kali root process can present equivalent uid/gid,
  and a process can impersonate an abstract endpoint during a restart. Use a
  non-replaceable sidecar-owned filesystem socket exposed read-only to Kali, or
  a mutually authenticated protocol with verifier identity pinned by the
  trusted runtime. Keep the capture volume absent from Kali and do not share
  the sidecar PID namespace.
- `AcceptEnv` may carry only a proof already issued by the trusted host control
  plane over the encrypted SSH session; it never establishes provenance by
  itself. The value must be scoped to the pre-command capture admission path,
  removed before participant execution, and absent from participant
  descendants. If the exact wrapper/client cannot meet that `/proc`,
  inheritance, or lifetime boundary, the upstream exact bytes must change;
  APTL must not compensate with a post-realization patch.
- Proof values and verifier/issuer private material stay in memory or a
  runtime-private descriptor/channel. They are never SDL, manifest, trial-plan,
  realization, Compose environment, durable env file, argv, process title,
  log, diagnostic, exception text, participant output, raw evidence, evidence
  metadata, or exported archive content. Public endpoint-verification material
  may be runtime-generated, but is not proof authority.
- `APTL_CAPTURE_CAPABILITY` is not currently classified by the shared redactor's
  token table. Add it as an exact sensitive key in the canonical Python and
  TypeScript redaction boundaries and parity corpus; do not classify every
  ordinary "capability" field as secret. Redaction is defense in depth, not
  permission to serialize proof material.

### Exact-byte realization boundary

The staged TechVault asset presently visible to APTL still uses anonymous ID
fallback, `mktemp -u`, an environment-inherited bearer, and an exit-70 override
when finalization fails. Those properties conflict with issue #939. Because
OpenRAE/env-packs#282 owns those bytes, completion requires consuming a new
digest-bound upstream asset that rejects invalid IDs, atomically creates a
private spool location, prevents participant inheritance/exposure, and
preserves command outcome separately from finalization. APTL must verify and
run those exact admitted bytes unchanged.

`scripts/envpack-kali-fixups.sh` is therefore not a migration seam. Remove it
and its `scripts/seed-prime.sh` invocation when the compatible pack digest is
consumed, and add a clean-realization assertion that the realized wrapper
digest equals the admitted artifact and contains no local marker or mutation.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical incumbent and required use |
|---|---|
| Capture admission | `aptl.core.experiment.capture_registry`, `capture_registrations`, `capture_mapping`, `trial_plan`, ADR-047, and the EXP-010 preflight. Extend `CaptureBinding`/trusted registration wiring; do not add a Kali policy table. |
| Capture lifecycle | `aptl.core.evidence.protocol`, `outcomes`, `coordinator`, `records`, and `aptl.core.execution.executor`. Preserve start-before-work, reverse finalization, typed loss, and one execution of `trial_body`. |
| Portable evidence | Public `raes_contracts` capture/evidence/run models, the EXP-010 evidence ledger, ADR-050 terminal archive, and `RunStorageBackend`/`LocalRunStore`. Admission receipts are internal bounded facts, not portable evidence records. |
| Kali isolation | ADR-041 and ADR-042; `containers/kali-capture`, the ForceCommand ingress, no Kali capture mount, no shared PID namespace, sidecar-owned PTY/kernel witnesses, and the existing `capture_container_name` harvest route. |
| SSH lifecycle | `mcp/aptl-mcp-common/src/{ssh-contracts,ssh-session,ssh-manager}.ts`, `SSHError`, session queues, remote-close latch, bound run ID, and `aptlShellEnv`. Inject a narrow issuer; do not create another SSH client/session manager. |
| Identity and clocks | `RunScope`, `aptl.core.correlation.ClockProvider`, correlation ID validation, `runstore`/`runs.ts` ID rules, and OBS-002. `_unbound` and `anon-*` may remain legacy storage labels but can never satisfy required capture admission. |
| Secrets and diagnostics | ADR-029, `aptl.utils.redaction`, TypeScript redaction parity, `aptl.utils.logging`, RAES `Diagnostic`, capture diagnostic codes, `LabResult`/`StartupDiagnostic`, and MCP result envelopes. Log codes, versions, safe IDs, counts, and durations only. |
| Paths and persistence | `aptl.utils.pathsafe`, secure `mkstemp`/private-directory patterns, content-addressed evidence insertion, create-once run records, and the sidecar-owned capture root. Derive paths from validated IDs; reject symlinks, special files, traversal, replacement, and append-to-finalized races. |
| Realization and readiness | RAES `RuntimeManager.apply`, `DeploymentBackend` realization/readback, `LabResult`, `StartupOutcome`, effective service-unit observation, and authenticated readiness polling patterns. Prove behavior, not marker-file or port presence. |
| Workflow | `.ground-control.yaml`, `.gc/plan-rules.md`, pytest, MCP vitest/rebuild rules, pre-commit, static TechVault gates, and clean `aptl lab stop -v && aptl lab start` validation for Compose/container/config changes. |

Kali PTY, pcap, audit, and process-accounting outputs are not the existing
`aptl.collector.mcp-red` JSON observation. Register only the capture kinds,
media types, artifact roles, limits, and visibility actually supported. The
current `CollectorOutcome` represents one media type/content object; if one
authored requirement needs several artifacts, extend the existing outcome and
ledger seam explicitly or bind separate authored requirements. Do not hide a
multi-artifact session inside an invented JSON wrapper.

## Security And Validation Passage

| Layer | Required passage |
|---|---|
| RAES shape and cross-artifact admission | Parse public RAES models, resolve refs, match every capture axis, and persist the binding before mutation. Unknown versions or unsupported required capture reject with `AdmissionRejection`. |
| Registry/runtime agreement | Verify registration ID, implementation version, effective-config digest, protocol version, media/role contract, and trusted adapter identity against the pinned binding before issuance. |
| Proof parser and policy | Bound frame/token size and field count; require a closed versioned shape; validate exact IDs, audience, runtime epoch, nonce, and clock window; reject unknown fields/algorithms and non-canonical or ambiguous encodings. |
| Issuer authority | Only trusted host composition holding the admitted binding and exact `RunScope` may issue. SSH credentials and workload-reachable endpoints cannot mint, widen, renew, or introspect authority. |
| Endpoint authentication | Separate the issuer/control channel from the workload data channel. Pin the verifier endpoint through an unreplaceable OS boundary or mutual authentication; peer uid, socket name, connect success, and `ping` alone are insufficient. |
| Config/environment | Keep `AptlConfig` strict and `EnvVars` as the durable environment authority. Protocol/audience/TTL ceilings are trusted registration/runtime policy, not SDL strings or MCP tool arguments. Never write bearer values to `.env` or realization env files. |
| OS/process exposure | No proof in argv, command strings, filesystem paths, process titles, Docker inspectable environment, diagnostics, or participant descendants. Create FIFO/private paths atomically under a `0700` directory; no `mktemp -u`. |
| Sidecar frame and path validation | Reuse the canonical ID rule plus semantic run/session/binding equality; bound JSON lines and decoded chunks; reject path/command/chmod/delete fields; create sinks no-follow and finalization-safe. |
| Error envelope | Extend the existing capture diagnostic domain with stable, non-disclosing rejection codes. Never return raw proof/parser/backend text, pydantic input, raw frames, socket paths, commands, or exception strings. Do not add a public exception hierarchy. |
| Readiness | A trusted, non-participant self-test must prove issuer availability, private delivery, verifier identity, protocol compatibility, atomic consume/replay rejection, sink writability, effective `sshd` policy, and bounded finalization. Publish through existing readiness/result DTOs; never equate a marker, live process, open port, or `pong` with readiness. |
| Evidence and export | Map interruption/finalization to existing collector outcomes and loss disclosure, persist through the content store/RAES ledger, and keep proof/receipt internals outside portable evidence and sealed/exported closure. |

## Extensibility Seam

The seam is a session-admission facet of a trusted collector registration,
parameterized by protocol version, audience/runtime epoch, proof lifetime
ceiling, endpoint-authentication method, and injected clock/randomness. The
next workload with required interactive capture should add a registration and
adapter behind that seam, not edit MCP tool schemas, create another token
format, or hard-code TechVault/Kali in the experiment controller.

Keep capture-class/artifact variation in the registry and collector outcome;
keep transport variation behind the session-admission adapter. Neither
variation may change run/session identity, portable evidence models, run-store
layout, or the SSH public API.

## Gotchas And Anti-Patterns

- Do not let `bool(started)` authorize work when any required binding is
  unavailable or failed startup.
- Do not key live or replay state by bare `session_id`; use the full bound
  run/session/audience/runtime identity, and consume the proof atomically.
- Do not use the current abstract socket name, `SO_PEERCRED`, uid allowlists,
  SSH key possession, or connection ownership as sufficient authentication
  against a passwordless-sudo Kali workload.
- Do not persist signing keys, bearer proofs, proof digests, or introspection
  state in SDL, manifests, generated content, Compose config, run records, or
  evidence. Runtime-private replay state is operational state, not evidence.
- Do not log raw frames or exception strings. The current sidecar/client style
  includes exception detail and paths; proof-sensitive paths must use stable
  codes only.
- Do not substitute `_unbound`, timestamp/PID `anon-*`, or a newly minted ID
  for missing or invalid admitted identity.
- Do not treat successful `ping`, service-unit activation, a readiness marker,
  a created directory, or artifact presence as proof of authenticated session
  admission, complete capture, or successful finalization.
- Do not override the real command result with capture finalization status,
  and do not reconnect/replay the command after capture loss.
- Do not patch staged exact content, weaken the wrapper after admission, add a
  second harvester/repository/evidence schema, or relabel legacy best-effort
  capture as satisfying a required binding.

## Non-Goals And Boundaries

- Changing TechVault-authored wrapper/client bytes or RAES portable semantics;
  consume their compatible released contracts when available.
- Replacing RAES capture/evidence/run schemas, EXP-010 policy, ADR-050 sealing,
  `LocalRunStore`, MCP session management, or the existing harvest layout.
- Creating a general credential service, OAuth/JWT platform, remote broker,
  database, generic plugin loader, or participant-visible proof API.
- Removing Kali passwordless sudo, making a malicious workload unable to cause
  denial of service, or proving terminal output semantically truthful.
- Securing every possible shell/container entry point; issue #939 owns admitted
  Kali SSH participant execution, while closed-world enforcement remains #916.
- Making red-side capture visible to the blue SIEM or weakening ADR-033
  non-contamination.
