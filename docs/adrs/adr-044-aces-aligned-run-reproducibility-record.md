# ADR-044: ACES-Aligned Run Reproducibility Record

## Status

accepted

## Date

2026-06-25

## Context

REP-001 requires every run to preserve enough information to reproduce or audit
the run after the TechVault cutover to ACES. The risk is not missing one field;
the risk is building a second APTL experiment manifest that duplicates ACES task,
run, apparatus, evidence, and provenance concepts under different names.

APTL already has the pieces this record must compose:

- ACES SDL parsing and semantic validation enter through `aces_sdl.parse_sdl_file`
  and the ACES `RuntimeManager`.
- APTL's backend capability claim is published by
  `src/aptl/backends/aces_manifest.py:create_aptl_manifest()`. The current
  code satisfies the `full-remote-control-plane` profile and passes the
  corresponding conformance tests; do not copy older `provisioning-only`,
  `orchestration-capable`, or `orchestration-evaluation` wording from dated
  planning records into new records.
- ACES provisioning, orchestration, and evaluation state is adapted through
  `AptlProvisioner`, `AptlOrchestrator`, `AptlEvaluator`,
  `AptlRealization`, `ApplyResult`, `RuntimeSnapshot`, operation
  receipt/status, workflow result/history, and evaluation result/history
  contracts.
- APTL backend realization evidence is already owned by `DeploymentBackend`,
  `capture_snapshot()`, `RangeSnapshot.to_dict()`, `LocalRunStore`,
  collectors, MCP run capture, and exporter packaging.
- ADR-029 makes `LocalRunStore.write_json`, `write_jsonl`, and
  `append_jsonl` the Python persistence serialization boundary for run
  archives, with `write_file` and `copy_file` explicitly pass-through.

## Decision

The REP-001 reproducibility record is a composition record. It anchors run
identity to ACES contracts where ACES has a contract, and it carries APTL-only
data only as backend realization evidence or evidence references.

When an ACES contract exists for a concept, the record stores that contract
payload or a stable identity reference to it. APTL does not define local
Pydantic/dataclass mirrors for ACES task, run, apparatus, evidence, provenance,
backend manifest, operation receipt/status, runtime snapshot, workflow, or
evaluation envelopes.

The record may include APTL backend sections for realization evidence such as
selected Docker Compose profiles, profile dependency closure, `AptlRealization`
details, range snapshot identity, config and image digests, detector/rule
content digests, tool versions, scenario parameters, seeds, and references to
MCP-side, Kali-side, SOC, container-log, and inventory evidence. Those sections
must be clearly backend-owned and must not become the canonical scenario or
runtime schema.

Runtime state has two distinct meanings and must stay separated:

- ACES `RuntimeSnapshot` is the portable ACES state/provenance surface.
- APTL `RangeSnapshot` is backend inventory evidence for the realized lab.

Both may be referenced by one run record, but neither replaces the other.

Structured run-record writes go through `LocalRunStore.write_json`,
`write_jsonl`, or `append_jsonl`. Opaque binary evidence can remain in existing
capture/export locations, but the structured reproducibility record should store
references and digests rather than copying bytes into a new JSON object.
Exporter code remains packaging-only and must not become the first redaction or
normalization point.

## Security Layers

| Layer | Requirement |
| --- | --- |
| ACES parser and validator gate | Scenario inputs continue through `aces_sdl.parse_sdl_file`, ACES semantic validation, `RuntimeManager.plan()`, and planner diagnostics. Do not structurally revalidate ACES SDL with local models. |
| Backend manifest and conformance gate | Backend identity comes from `create_aptl_manifest()` and its serialized ACES backend-manifest-v2 payload, including supported contract versions, compatible processors, realization support, concept bindings, provisioner, orchestrator, and evaluator capability declarations. |
| Runtime contract gate | Operation receipt/status, ACES `RuntimeSnapshot`, workflow result/history, and evaluation result/history are the portable runtime surfaces. Backend exceptions are translated into redacted ACES diagnostics or `LabResult` errors at the adapter boundary. |
| Deployment inventory gate | Docker, Compose, container, network, image, port, and host inventory flows through `DeploymentBackend` and existing snapshot helpers. Do not parse `docker-compose.yml` or call raw Docker from a record builder. |
| Config and env binding | Durable non-secret settings come from strict `AptlConfig`; runtime secrets come from `.env` / `EnvVars`, placeholder checks, ADR-028 generated config, and ADR-034 SOC TLS material. The record may store digests and non-secret identities, not `.env` values, rendered config secrets, API tokens, cookies, private keys, or bearer material. |
| Persistence and path containment | `LocalRunStore` owns run IDs, relative-path validation, run directory layout, and redacted JSON/JSONL writes. New record paths must use those methods and inherit their traversal checks. |
| Snapshot serialization | APTL range inventory enters JSON through `RangeSnapshot.to_dict()`, preserving ADR-029 redaction for service credentials and other secret-shaped fields. |
| Collector and SOC HTTP safety | Collectors stay fault-tolerant, log counts/status only, and use `curl_safe` where SOC API calls need token/body handling that avoids argv leakage. |
| API and error envelope | If the record is later exposed through the web API, it must use the existing `verify_token` / `WebAuthSettings` boundary and existing Pydantic response projection style. Error text must be generic and redacted; auth tokens do not travel in URLs. |
| OS/process exposure | Do not introduce subprocess calls that put tokens, hashes, cookies, passwords, private key material, or rendered secret config in process argv. File modes and ignored directories are defense in depth only. |
| Export boundary | `exporter.py` packages already-safe run artifacts and computes checksums. It must not mutate records to hide leaks that were written earlier. |

## Maintainability

Canonical incumbents for REP-001 are:

- `src/aptl/backends/aces_manifest.py` for backend identity and supported ACES
  contract versions.
- `src/aptl/backends/aces.py`,
  `src/aptl/backends/aces_realization.py`,
  `src/aptl/backends/aces_realization_model.py`,
  `src/aptl/backends/aces_orchestrator.py`,
  `src/aptl/backends/aces_evaluator.py`, and
  `src/aptl/backends/aces_diagnostics.py` for the ACES adapter boundary.
- `src/aptl/core/deployment/` for all Docker/Compose/container/host
  interaction.
- `src/aptl/core/snapshot.py` and `src/aptl/core/endpoints.py` for APTL range
  inventory and endpoint annotation.
- `src/aptl/core/runstore.py`, `src/aptl/core/collectors.py`, and
  `src/aptl/core/exporter.py` for run archive persistence, collection, and
  packaging.
- `src/aptl/core/session.py` and `src/aptl/core/telemetry.py` for
  cross-process trace/run correlation.
- `src/aptl/core/config.py`, `src/aptl/core/env.py`,
  `src/aptl/core/credentials.py`, and `src/aptl/utils/redaction.py` for
  config, env, generated secret handling, and serialization redaction.
- `mcp/aptl-mcp-common/src/runs.ts`,
  `mcp/aptl-mcp-common/src/redaction.ts`, and `mcp/mcp-red/src/capture.ts`
  for TypeScript-side run capture and redaction parity.

Tests should extend the existing seams rather than introduce new harnesses:
`tests/test_aces_backend.py`, `tests/test_snapshot.py`,
`tests/test_runstore.py`, `tests/test_exporter.py`, `tests/test_collectors.py`,
`tests/test_session.py`, and the MCP redaction/run-capture tests.

## Extensibility

The extensibility seam is the boundary between ACES contract identity and APTL
backend evidence references.

Future ACES contract additions for task/run/apparatus/evidence/provenance should
replace APTL-specific placeholders at the ACES namespace, without changing the
backend evidence namespace. Future APTL evidence sources should add a referenced
evidence kind plus digest/path metadata under the backend evidence namespace,
without editing ACES contract payloads or hardcoding TechVault-specific fields.

The record must be parameterized by backend name, backend manifest version,
supported contract versions, compatible processor identity, scenario identity,
and run identity. It must not assume TechVault is the only scenario, Docker
Compose is the only possible APTL backend forever, or that the current manifest
profile string is static.

## Non-Goals

- Do not design a new APTL scenario schema, experiment manifest schema, or ACES
  mirror schema.
- Do not promote `RangeSnapshot` to the ACES `RuntimeSnapshot` role or flatten
  ACES runtime state into APTL snapshot fields.
- Do not redesign run archive layout, exporter packaging, OTel tracing,
  MCP capture, web auth, deployment backends, or config/env binding as part of
  REP-001.
- Do not make the run archive a plaintext secret vault or full forensic image.
- Do not add a new exception hierarchy, validation framework, redaction helper,
  or logging taxonomy for reproducibility records.
- Do not change APTL's backend profile claim as part of the record unless the
  ACES manifest and conformance tests change in the same backend-focused work.

## Anti-Patterns

- Creating `ExperimentManifest`, `AcesRunManifest`, or similar local types that
  restate ACES contract fields.
- Storing backend-specific evidence at the top level so it looks portable.
- Treating image tags as image identity when a digest is available.
- Treating `.env` hashes or file permissions as permission to expose `.env`
  values, rendered config secrets, tokens, or private keys.
- Calling `docker`, `docker compose`, `curl`, or `ssh` directly from a record
  builder instead of using the existing backend, collector, or safe-curl
  boundary.
- Copying raw evidence into JSON through `write_file` / `copy_file` and assuming
  the runstore redacted it.
- Letting API, CLI, or exporter code become a second normalizer for the same
  record shape.
- Hardcoding TechVault scenario names, compose profile names, or a stale backend
  profile string in the canonical record.

## References

- [ADR-023](adr-023-container-interaction-in-deployment-backend.md): container
  interaction belongs on the deployment backend.
- [ADR-029](adr-029-control-plane-secret-handling.md): runstore and snapshot
  redaction boundaries.
- [ADR-033](adr-033-agent-reasoning-trace-boundary.md): per-run MCP/Kali capture
  layout and trace correlation.
- [ADR-035](adr-035-aces-sdl-adoption.md): ACES adoption and adapter guardrails.
- [ADR-036](adr-036-snapshot-endpoint-registry.md): snapshot endpoint registry
  boundary.
- [ADR-039](adr-039-web-control-plane-authentication.md): web API auth and error
  boundary.
- [ADR-041](adr-041-kali-capture-sidecar-ownership-boundary.md) and
  [ADR-042](adr-042-sidecar-owned-pty-master.md): Kali capture ownership and
  transcript authenticity.
- REP-001 / GitHub issue #423.
