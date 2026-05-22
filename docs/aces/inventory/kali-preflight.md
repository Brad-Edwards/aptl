# Kali ACES Inventory Preflight

This note is the architecture preflight for SCN-010 / issue #339. It is a
binding guardrail for the Kali steady-state inventory, not a replacement for
ADR-035, ADR-033, ADR-029, or the ACES asset-inventorying methodology.

## Architecture Decisions

- The completion artifact is an ACES inventory bundle under
  `docs/aces/inventory/kali/`, using the existing `mapping-ledger.yaml`
  schema, `aptl aces-inventory validate`, and the evidence/checksum shape
  already used by `shuffle-backend` and `webapp`.
- The inventory describes the realized `aptl-kali` container at one
  post-`aptl lab start` steady-state snapshot. If the capture is not from a
  destructive clean reset, record that boundary explicitly and do not claim
  clean-lab reproducibility or byte-identical rebuildability.
- `scenarios/techvault.sdl.yaml` remains an ACES SDL document whose authority
  is the sibling ACES parser and runtime compiler. Do not validate Kali
  additions through `aptl.core.sdl`, `aptl.core.scenarios`, or a local mirror
  of ACES models.
- Keep three concepts separate: the ACES red-side node/agent surface, the APTL
  Docker Compose realization, and ADR-033 experimental capture/runstore data.
  Participant-visible Kali facts must be captured and mapped; run archive and
  harvest mechanics stay owned by ADR-033, `LocalRunStore`, and the MCP common
  capture boundary.
- Kali is not a target host for declared scenario weaknesses. Scanner CVEs and
  patch state belong in runtime/package inventory evidence unless ACES has a
  more specific non-target weakness surface.
- Missing ACES expressivity must be represented as an upstream ACES blocker.
  APTL backend consumption gaps do not justify leaving an observable fact as
  evidence-only for this inventory issue.

## Cross-Cutting Concerns To Reuse

- Inventory methodology and ledger validation:
  `docs/aces/inventory/asset-inventory-methodology.md`,
  `src/aptl/core/aces_inventory.py`, `src/aptl/cli/aces_inventory.py`, and
  `tests/test_aces_inventory_methodology.py`.
- Prior asset patterns:
  `docs/aces/inventory/shuffle-backend/`,
  `docs/aces/inventory/webapp/`,
  `docs/aces/inventory/webapp-preflight.md`, and
  `tests/test_webapp_inventory.py`.
- ACES adoption and parity routing:
  ADR-035, `docs/aces/parity-inventory.yaml`,
  `docs/aces/parity-inventory.md`, and `tests/test_parity_inventory.py`.
- Kali realization owners:
  `docker-compose.yml` service `kali`, `containers/kali/Dockerfile`,
  `containers/kali/entrypoint.sh`, `containers/kali/healthcheck.sh`,
  `containers/kali/scripts/aptl-wrap-shell.sh`,
  `containers/kali/audit/aptl.rules`, and
  `docs/components/kali-redteam.md`.
- Runtime/control-plane owners:
  `AptlConfig`, `ContainerSettings.enabled_profiles()`, `EnvVars`,
  `_LAB_START_STEPS`, `DeploymentBackend`, `LabResult`,
  `StartupDiagnostic`, `RangeSnapshot.to_dict()`, `LocalRunStore`, and the
  MCP run/capture helpers mirrored under `mcp/aptl-mcp-common`.
- Shared safety helpers and policies: ADR-028, ADR-029, ADR-033, ADR-036,
  ADR-037, `aptl.utils.redaction.redact`, and `aptl.utils.curl_safe` when
  commands would otherwise put credentials in process argv.

## Security And Validation Layers

- **ACES SDL shape:** Kali SDL additions must parse with
  `aces_sdl.parse_sdl_file` and compile through the ACES runtime compiler.
  Do not add local structural validators for ACES fields.
- **Inventory ledger:** every captured fact needs an existing
  `AcesSurface` mapping, caveat, or linked ACES issue in
  `mapping-ledger.yaml`. No `needs_gap_triage` rows should remain at review.
- **Secret classification:** ADR-029 is canonical. Operator secrets, private
  SSH keys, bearer tokens, cookies, generated service config, and arbitrary
  prior run transcripts must not be committed unredacted. Intentional target
  fixture credentials may be encoded only when they are participant-visible
  scenario facts with an explicit `secret_fixture`-style classification.
- **Kali capture data:** ADR-033 capture surfaces can contain full argv, hidden
  PTY input, raw pcap bytes, and prior experiment data. A non-empty
  `kali_captures` volume is evidence to account for, but it is not safe to
  commit wholesale. Prefer fresh-volume capture for this inventory; otherwise
  record contamination and redact or checksum sensitive content.
- **Config and env binding:** durable toggles remain in strict `AptlConfig`.
  `.env` parsing and placeholder rejection remain in `EnvVars` /
  `find_placeholder_env_values`. Do not add ACES-specific environment parsing
  for Kali. Compose `VICTIM_IP` and SSH `APTL_*` session env vars are
  different surfaces and must not be collapsed.
- **OS/process exposure:** inventory capture commands must not place private
  keys, passwords, hashes, tokens, or replayable IDs in argv, logs, or
  exception text. Store command provenance, not secret-bearing command lines.
- **Runtime isolation:** preserve ADR-033 non-contamination. No Wazuh agent,
  rsyslog forwarding, or red-to-SIEM pipe belongs in Kali evidence or future
  fixes unless a later ADR explicitly overrides ADR-033.
- **Container security shape:** encode the difference between Compose
  `cap_add`, `seccomp:unconfined`, Docker `init: true`, the entrypoint's
  `capsh --drop=cap_audit_control` behavior, and healthcheck degraded
  subsystem reporting. Do not flatten them into one generic privilege flag.
- **Error envelopes and observability:** any new CLI/test helper must report
  narrow diagnostics and reuse redaction. Raw Docker, scanner, SSH, or ACES
  exception payloads must not cross CLI, log, API, snapshot, or runstore
  boundaries unfiltered.

## Extensibility Seam

The seam is the versioned inventory ledger plus ACES runtime fields for one
asset id, source class, and Compose service. A future red-side asset or custom
build should reuse the same schema and test fixture pattern by changing asset
parameters, not by extending the validator with Kali-specific branches.

For the SDL, parameterization belongs in ACES-native node, source, runtime,
agent, relationship, content, and account fields. Backend realization remains
behind the ACES backend profile and existing APTL owners.

## Gotchas And Anti-Patterns

- Do not reuse a "representative paths only" filesystem claim silently. This
  issue asks for participant/agent-observable steady-state facts, including
  logs, caches, generated state, and volume contents. If a full enumeration is
  not done, record the exact claim boundary and leave remaining facts encoded
  later or blocked by ACES expressivity.
- Do not encode stale public SSH port assumptions. Current Compose declares no
  host port for `kali`; the control plane reaches it by container IP.
- Do not treat `kalilinux/kali-last-release:latest` as immutable. Pair the
  mutable base tag and local image tag with observed digests, layers, package
  manifests, and scanner versions.
- Do not confuse scanner findings with authored vulnerabilities on a target
  host.
- Do not model auditd/procacct as fully available unless the readiness marker
  and health log show those subsystems as `ok`; healthy Kali can still be
  capture-degraded.
- Do not hide missing ACES expressivity in `metadata`, `x-aptl-*`, comments,
  evidence-only ledgers, or TechVault-name dispatch.
- Do not create a second scenario schema, second inventory validator, second
  secret taxonomy, second readiness taxonomy, or new exception hierarchy.
- Do not repair Kali inventory findings by changing Docker Compose,
  container startup, capture plumbing, or red/blue visibility in this issue.

## Non-Goals

- Do not implement the inventory, capture evidence, edit TechVault SDL, or add
  tests from this preflight.
- Do not run `aptl lab stop -v && aptl lab start` unless the user explicitly
  authorizes destroying the current lab state.
- Do not implement the ACES backend interpreter, default-scenario flip,
  legacy SDL deletion, scenario archive move, or Phase B cutover.
- Do not redesign ADR-033 capture ownership, close the Kali tamper-resistance
  follow-up, redesign run archives, or add a red-to-SIEM path.
- Do not use APTL runtime consumption gaps as a substitute for ACES SDL
  expression or ACES expressivity blockers.
