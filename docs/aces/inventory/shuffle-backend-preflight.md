# Shuffle Backend ACES Inventory Preflight

This note records the architecture preflight for SCN-010 / issue #360. It is a
binding guardrail for the Shuffle backend steady-state inventory and TechVault
ACES SDL encoding, not a replacement for ADR-035, ADR-029, or the ACES
asset-inventory methodology.

The existing `docs/aces/inventory/shuffle-backend/` bundle began as an APTL
#353 methodology smoke pass from an already-running lab. Later classification
audit work consumed ACES #354 and encoded the captured runtime facts in
`scenarios/techvault/nodes/shuffle-backend.sdl.yaml`. Do not treat the smoke
pass as a clean-lab, issue #360 completion artifact unless the evidence,
ledger, README scope, checksums, and parity inventory all say that boundary was
intentionally updated.

## Architecture Decisions

- Keep the work as a downstream ACES inventory and ACES SDL authoring update.
  Evidence files, Docker output, scanner output, checksums, and the
  `mapping-ledger.yaml` are proof and handoff artifacts only; every
  ACES-expressible participant/agent-observable fact belongs in
  `scenarios/techvault/nodes/shuffle-backend.sdl.yaml`.
- ACES remains the SDL authority. Validate SDL additions with the sibling
  ACES parser/runtime compiler, not `aptl.core.sdl`, `aptl.core.scenarios`, a
  local Pydantic mirror, or an APTL-only semantic interpretation.
- APTL remains the downstream ledger and realization validator. Reuse the
  versioned `mapping-ledger.yaml` schema and `aptl aces-inventory` CLI; do not
  add a second inventory schema, local ACES model, or Shuffle-specific
  validation branch.
- The current ACES runtime fields already cover the captured image identity,
  OS, network identity, API listener, environment classification, volume mount,
  Docker socket control interface, process identity, package inventory, Go
  manifest, container policy, and package-vulnerability scanner state. New
  gaps require an ACES issue after checking current ACES lineage and
  surfaces; APTL backend consumption gaps do not justify evidence-only facts.
- Keep Compose delivery concepts separate from authored scenario facts. The
  `soc` profile and Docker realization are backend responsibilities; the
  participant-visible Shuffle backend state is an ACES SDL node/runtime
  surface.
- A clean steady-state claim requires evidence from the stated snapshot point.
  If implementation does not perform a fresh `aptl lab start` capture, record
  that as a first-class `capture-limits.txt`, README, ledger, and parity
  boundary.

## Cross-Cutting Concerns To Reuse

- ACES-owned methodology and capture skill:
  `../aces-sdl/docs/aces/inventory/asset-inventory-methodology.md` and
  `../aces-sdl/.codex-skills/aces-asset-inventory-capture/`.
- APTL downstream inventory contract:
  `docs/aces/inventory/asset-inventory-methodology.md`,
  `src/aptl/core/aces_inventory.py`, `src/aptl/cli/aces_inventory.py`, and
  `tests/test_aces_inventory_methodology.py`.
- Existing Shuffle artifacts:
  `docs/aces/inventory/shuffle-backend/README.md`,
  `docs/aces/inventory/shuffle-backend/mapping-ledger.yaml`,
  `docs/aces/inventory/shuffle-backend/evidence/`, and
  `scenarios/techvault/nodes/shuffle-backend.sdl.yaml`.
- ACES adoption and parity routing:
  ADR-035, `docs/aces/parity-inventory.yaml`,
  `docs/aces/parity-inventory.md`, `tests/test_parity_inventory.py`, and
  `tests/test_techvault_classification_audit.py`.
- Realization owners:
  `docker-compose.yml` service `shuffle-backend`, `shuffle_data`, the
  `aptl-security` network, `src/aptl/core/deployment/backend.py`,
  `src/aptl/core/deployment/docker_compose.py`, `src/aptl/core/lab.py`, and
  `src/aptl/core/lab_types.py`.
- Config and secret handling:
  `AptlConfig`, `ContainerSettings.enabled_profiles()`, `EnvVars`,
  `find_placeholder_env_values`, ADR-029, `aptl.utils.redaction.redact`, and
  `aptl.utils.curl_safe` for token-bearing command boundaries.

## Security And Validation Layers

- **ACES parser/compiler:** SDL changes must parse with
  `aces_sdl.parse_sdl_file` and compile through the ACES runtime compiler.
  Structural validation belongs there, not in a new APTL schema.
- **Inventory ledger:** every captured fact needs evidence and an
  `encoded`, `encoded_with_caveat`, or linked gap disposition in the existing
  ledger schema. No `needs_gap_triage` row should survive review.
- **Evidence references and checksums:** every committed evidence file must be
  referenced by the ledger and covered by `evidence-sha256sums.txt`; checksum
  drift is a real artifact change, not a formatting cleanup.
- **Secret classification:** ADR-029 is canonical. Redact
  `SHUFFLE_DEFAULT_APIKEY`, `SHUFFLE_DEFAULT_PASSWORD`,
  `SHUFFLE_OPENSEARCH_PASSWORD`, bearer tokens, cookies, private keys,
  generated config secrets, and replayable IDs before they cross evidence,
  CLI, log, trace, issue-comment, or exception boundaries. Scenario fixture
  values may be retained only when classified as participant-visible facts.
- **Config and env binding:** durable toggles stay in strict `AptlConfig`;
  `.env` parsing and placeholder rejection stay in `EnvVars` and
  `find_placeholder_env_values`. Do not add ACES-specific env parsing for
  Shuffle.
- **OS/process exposure:** capture and helper commands must not put raw
  secrets in process argv, shell history, logs, Docker inspect output, scanner
  output, or traceback text. Record command provenance without replayable
  secret values.
- **Runtime realization:** Docker/Compose state is observed through the
  existing backend/lab surfaces. Do not repair inventory findings by changing
  Compose, host port exposure, profile selection, or startup behavior in this
  inventory issue.
- **Error envelopes and observability:** new helper diagnostics must stay
  narrow and redacted. Raw Docker, scanner, ACES, or Compose exceptions should
  not be copied verbatim into CLI/API output, logs, run archives, or evidence
  notes.

## Extensibility Seam

The seam is the tuple of asset id, Compose service, ACES node/runtime fields,
and versioned mapping ledger. Future upstream-image SOC assets should reuse the
same capture resources, ledger validator, SDL runtime fields, and regression
fixture pattern by changing those parameters, not by adding a new parser,
schema, exception hierarchy, or service-specific workflow.

If a future ACES profile promotion needs to realize these fields at runtime,
that belongs behind the ACES backend target and existing APTL
`DeploymentBackend`/`LabResult` boundaries. Do not make
`shuffle-backend`-named dispatch part of the public backend contract.

## Gotchas And Anti-Patterns

- Do not close issue #360 on the old methodology smoke-pass claim if the
  acceptance criteria require a fresh steady-state asset spec.
- Do not leave a captured fact as evidence-only when ACES can express it.
- Do not hide missing ACES expressivity in comments, `description`,
  `metadata`, `x-aptl-*`, the parity inventory, or the mapping ledger.
- Do not collapse the writable Docker socket into a generic mount only; it is
  also a local control interface and trust surface.
- Do not confuse mutable image tag, immutable digest, image-id hash, rootfs
  layers, registry attestations, SBOM identity, and scanner database state.
- Do not treat Trivy findings as authored scenario vulnerabilities; they are
  time-sensitive package-vulnerability scanner state unless the scenario
  deliberately declares a weakness.
- Do not reintroduce a host-published plaintext `5001` Shuffle backend path.
  Current Compose intentionally keeps the backend intra-cluster behind the
  HTTPS frontend.
- Do not create a second secret taxonomy, redaction helper, ACES parser,
  inventory validator, readiness taxonomy, or runtime exception hierarchy.

## Non-Goals

- Do not implement the inventory, refresh evidence, edit TechVault SDL, or add
  tests from this preflight.
- Do not run `aptl lab stop -v && aptl lab start` unless the user explicitly
  authorizes destroying current lab state.
- Do not implement the ACES backend interpreter, profile promotion,
  default-scenario flip, legacy SDL deletion, scenario archive move, or Phase B
  cutover.
- Do not change Docker Compose, Shuffle startup behavior, host exposure,
  generated SOC config, run archives, collectors, or APTL runtime consumption
  to make an inventory fact easier to encode.
