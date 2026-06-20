# MISP Redis ACES Inventory Preflight

This note records the architecture preflight for SCN-010 / issue #348. It is a
binding guardrail for the `misp-redis` steady-state inventory and TechVault
ACES SDL encoding, not a replacement for ADR-035, ADR-029, ADR-028, ADR-037,
or the ACES asset-inventory methodology.

## Architecture Decisions

- Keep the work as a downstream ACES inventory and ACES SDL authoring update.
  Evidence files, Docker output, scanner output, checksums, and
  `mapping-ledger.yaml` are proof inputs only; every ACES-expressible
  participant/agent-observable Redis fact belongs in the TechVault ACES SDL.
- In this checkout, the editable TechVault node surface is the imported
  `scenarios/techvault/nodes/misp-redis.sdl.yaml`; the composed authority is
  still `scenarios/techvault.sdl.yaml`, parsed by ACES. Do not fork the root
  structure or validate additions with `aptl.core.sdl`.
- Treat `misp-redis` as a scenario node, not merely an implementation detail of
  MISP. It is a participant-discoverable backing service on `aptl-security`
  with its own image identity, command, process, listener, package, filesystem,
  scanner, network, and relationship facts.
- Keep Compose delivery concepts separate from authored facts. The `soc`
  profile, lack of host-published ports, lack of static IP, restart policy,
  resource limit, no local Dockerfile, and no named volume are realization
  facts to capture and map; they are not a reason to skip SDL expression.
- The Compose command declares Redis password enforcement. The existence of
  password auth and the fixture value are in-scope service facts because they
  are authored TechVault scenario content. Preserve the value verbatim in the
  capture surfaces that expose it and cite the checked-in Compose source as
  provenance.
- Missing ACES expressivity is an upstream ACES blocker. Do not use APTL backend
  consumption gaps, free-text comments, `metadata`, or `x-aptl-*` fields to
  leave catalogued Redis facts evidence-only.

## Cross-Cutting Concerns To Reuse

- ACES-owned methodology and capture workflow:
  `../aces-sdl/docs/aces/inventory/asset-inventory-methodology.md` and
  `../aces-sdl/.codex-skills/aces-asset-inventory-capture/`.
- APTL downstream ledger contract:
  `src/aptl/core/aces_inventory.py`, `src/aptl/cli/aces_inventory.py`,
  `aptl aces-inventory validate`, `aptl aces-inventory gaps`, and the existing
  versioned `mapping-ledger.yaml` schema.
- Prior companion-asset patterns:
  `docs/aces/inventory/misp/`, `docs/aces/inventory/misp-db/`,
  `tests/test_misp_inventory.py`, and `tests/test_misp_db_inventory.py`.
- ACES adoption and parity routing:
  ADR-035, `docs/aces/parity-inventory.yaml`,
  `docs/aces/parity-inventory.md`, `tests/test_parity_inventory.py`, and
  `tests/techvault_sdl.py`.
- Redis realization owners:
  `docker-compose.yml` service `misp-redis`,
  `scenarios/techvault/nodes/misp-redis.sdl.yaml`,
  `scenarios/techvault/sections/infrastructure.sdl.yaml`,
  `scenarios/techvault/sections/relationships.sdl.yaml`, and
  `scenarios/techvault/sections/features.sdl.yaml`.
- Runtime/control-plane owners:
  `DeploymentBackend`, `DockerComposeBackend`, `LabResult`,
  `StartupDiagnostic`, `RangeSnapshot.to_dict()`, and `LocalRunStore` for
  runtime consumers. Inventory capture may collect Docker evidence, but runtime
  APTL code must not add raw Docker subprocess calls around these boundaries.
- Shared safety helpers and policy:
  ADR-029, ADR-028, ADR-037, and `aptl.utils.curl_safe` for command forms that
  would otherwise introduce extra non-scenario credentials into process argv.

## Security And Validation Layers

- **ACES parser/compiler:** SDL changes must parse with
  `aces_sdl.parse_sdl_file` and compile through the ACES runtime compiler.
  Structural validation belongs to ACES, not a new APTL schema or Pydantic
  mirror.
- **Inventory ledger:** every captured fact needs evidence and an `encoded`,
  `encoded_with_caveat`, or linked gap disposition in the existing ledger
  schema. No `needs_gap_triage` row should survive review.
- **Evidence references and checksums:** every committed evidence file must be
  referenced by the ledger and covered by `evidence/evidence-sha256sums.txt`.
  Checksum drift is an artifact change, not a formatting cleanup.
- **Secret classification:** `redispassword` is a designed lab fixture already
  present in Compose. It is TechVault scenario content and must be retained
  verbatim in Docker inspect output, process listings, logs, runtime baselines,
  scanner output, README prose, ledgers, and tests when those surfaces expose
  it.
- **OS/process exposure:** `redis-server --requirepass ...` is visible through
  process argv and Docker command metadata. Redis probes must not introduce
  extra raw-password argv forms such as `redis-cli -a <value>` into captured
  output. Record command provenance without replayable credential values.
- **Config and env binding:** do not move the Redis credential into
  `AptlConfig`, `.env`, or generated config as part of this inventory. Durable
  config remains under `AptlConfig`; env and placeholder validation remain in
  `EnvVars` / `find_placeholder_env_values`.
- **Docker/Compose boundary:** capture the existing Compose realization; do not
  repair inventory findings by changing `docker-compose.yml`, profiles, host
  exposure, startup behavior, or Redis auth in this issue. Future runtime code
  must still use `DeploymentBackend` rather than raw Docker calls.
- **Error envelopes and observability:** new helper diagnostics, tests, or CLI
  calls must stay narrow and must not introduce unrelated non-scenario
  credentials. Scenario target evidence remains verbatim; raw Docker, scanner,
  ACES, Redis, or Compose exception payloads outside the capture bundle should
  not be copied into CLI/API output, logs, run archives, or issue comments.

## Extensibility Seam

The seam is the tuple of asset id, Compose service, ACES node/runtime fields,
relationship fields, and the versioned mapping ledger. Future backing-store
assets should reuse the same capture resources, ledger validator, SDL runtime
fields, and regression-test fixture pattern by changing those parameters, not
by adding a new parser, schema, exception hierarchy, or service-specific
workflow.

For Redis-specific detail, parameterization belongs in ACES-native service,
runtime command/process, listener, package, filesystem, network, credential
classification, and relationship fields. A later ACES backend profile
promotion must realize those fields behind the ACES backend target and existing
APTL `DeploymentBackend`/`LabResult` boundaries, not through
`misp-redis`-named dispatch.

## Gotchas And Anti-Patterns

- Do not leave the current stub node as the final claim. `source.name`,
  `source.version`, `services[6379]`, and `os: linux` are not enough for issue
  #348.
- Do not treat "upstream image, no Dockerfile" as no build/provenance surface.
  Capture the mutable tag, resolved digest, image id, history, layers, package
  manifests, scanner versions, and absent attestation status.
- Do not infer "no persistent state" only from the absence of a named volume.
  Redis may still have participant-observable filesystem, config, logs, COW
  layer state, process state, and startup artifacts at the snapshot point.
- Do not confuse package CVEs with authored scenario vulnerabilities. Redis is
  a defensive SOC backing store unless a scenario weakness is deliberately
  declared on it.
- Do not collapse network reachability into a single service declaration. The
  lack of a static IP or published host port, the `aptl-security` endpoint,
  Docker aliases/DNS names, Docker embedded DNS listeners, and participant
  discovery vantage results are distinct facts.
- Do not leave the existing MISP-to-Redis relationship caveat stale if Redis
  evidence resolves part of it. Update relationship fields only to the extent
  the new Redis-side or participant-probe evidence actually proves them.
- Do not hide missing ACES expressivity in descriptions, comments, metadata,
  parity inventory rows, evidence-only ledger facts, or backend-specific
  shortcuts.
- Do not create a second inventory validator, second ACES model, second secret
  taxonomy, Redis-specific exception hierarchy, or Docker command passthrough.

## Non-Goals

- Do not implement the inventory, capture evidence, edit TechVault SDL, add
  tests, or file ACES gaps from this preflight.
- Do not run `aptl lab stop -v && aptl lab start` unless the user explicitly
  authorizes destroying current lab state.
- Do not implement the ACES backend interpreter, profile promotion,
  default-scenario flip, legacy SDL deletion, scenario archive move, or Phase B
  cutover.
- Do not change Redis authentication, Compose service shape, generated config,
  MISP startup behavior, host exposure, run archives, collectors, or APTL
  runtime consumption to make an inventory fact easier to encode.
- Do not use APTL runtime support gaps as a substitute for ACES SDL expression
  or ACES expressivity blockers.
