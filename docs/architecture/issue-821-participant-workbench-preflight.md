# Issue #821 Participant Workbench Preflight

This note sets the design guardrails for the in-appliance participant
workbench. It is guidance, not an implementation plan. [ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md)
is the delivery-boundary decision; ADR-029, ADR-033, ADR-034, ADR-039 through
ADR-042, and DSL-010 remain authoritative for secrets, evidence, TLS,
browser/operator controls, Kali capture, and ACES participant runtime.

No new ADR is needed. The remaining ambiguity is profile isolation: a client
that merely hides a tool, while its process can read another profile's config
or credentials, does not satisfy this issue.

## Architecture Decisions And Guardrails

- One desktop endpoint is a participant UX property, not authority placement.
  The browser or remote-desktop presentation sits in the participant zone;
  the supported coding agent, MCP client, and every APTL MCP server run in a
  management-zone runtime compartment inside the appliance. The participant
  endpoint has no Docker socket, management credential, model credential,
  blue credential, runstore mount, or direct SOC-management route.
- The participant listener is a separate route assembly and network listener,
  not the ADR-039 operator API with a participant role check. It may reuse
  BFF/session/Host/CSRF mechanics where their semantics fit, but never its
  bearer token, lifecycle, kill, config mutation, arbitrary terminal, raw
  evidence, or Docker-facing routes. The existing terminal endpoint is an
  operator surface, not a workbench shortcut.
- A profile is an enforced launch compartment, not a UI filter. The launcher
  admits exactly one of the fixed `red` or `blue` profile identifiers, starts
  a fresh agent/MCP process set with only that profile's generated connection
  config, credentials, mounts, egress rules, and bookmarks, and stops the old
  set before switching. It must not mount both configs and toggle a client
  preference, nor rely on the model to obey a tool-selection instruction.
- For the current operational scenario, `red` exposes `aptl-red` only; an
  optional reverse-engineering server is red-side only when the admitted
  scenario realizes that capability. `blue` exposes only `aptl-indexer`,
  `aptl-wazuh`, `aptl-network`, `aptl-threatintel`, `aptl-casemgmt`, and
  `aptl-soar`. Red never receives the credential aliases required by blue
  servers, blue never receives a Kali MCP connection, and neither profile
  receives Docker authority. The exact `tools/list` inventory, not just the
  server-name list, is the acceptance contract.
- Treat the participant, its prompt content, and the coding agent as
  potentially compromised. A profile compartment must therefore be unable to
  discover or execute the other profile's built entrypoints, read its config
  or secret state, alter authoritative run/evidence state, or address an
  undeclared zone. Management placement alone is not sufficient when the
  agent has a shell or file-access tool.
- Purple work is a sequential, explicit profile transition. It records the
  selected profile and transition outcome against the current run identity,
  but does not create a second ACES scenario/episode/evidence schema or make a
  profile switch an alias for participant-episode reset, scenario reset,
  Compose teardown, or guest security reset.
- Session-local model authentication is guest-management-only mutable state.
  It is injected after boot through the ADR-049 bootstrap boundary, never
  placed in images, static assets, URLs, browser storage, profile JSON, MCP
  config, command lines, environment dumps, logs, captures, or support
  bundles. Normal profile close revokes/destroys session state after ordered
  agent/MCP shutdown and telemetry/evidence flush; guest replacement remains
  the security reset after compromise.
- Participant-visible bookmarks are non-secret presentation data for only
  permitted appliance gateway routes. They must not contain host-loopback
  URLs, Docker IPs, credentials, tokens, or SOC-management backdoors.
  `ENDPOINT_REGISTRY` may supply existing display metadata where appropriate,
  but its host-published URL projection is not the participant policy or a
  substitute for the default-deny flow matrix.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical owner and required reuse |
|---|---|
| Appliance boundary and zones | ADR-049, especially APP-003 through APP-009, owns per-seat guest containment, default-deny flows, management placement, secrets, evidence, and replacement. The VM is not an ACES node provider or a reason to fork Compose/scenario contracts. |
| Participant/runtime semantics | `AptlParticipantRuntime`, published ACES participant contracts, `RuntimeControlPlane`, and DSL-010 own episodes, actions, receipts, status, snapshots, and behavior history. A profile is not another participant DTO or workflow state machine. |
| MCP build and server behavior | `mcp/build-all-mcps.sh`, `.mcp.json.example`, `LabConfig`, `loadLabConfig()`, `createMCPServer()`, JSON Schema tool definitions, handler assertions, `HTTPClient`, endpoint-origin checks, SSH lifecycle, TLS/CA support, and `aptl-mcp-common` remain the server contracts. A selected profile must use built artifacts and guest-internal generated configuration, not host-relative source execution. |
| Existing config limitation | `aptl.core.lab._sync_mcp_config_keys()` and `.mcp.json` are developer-local conveniences: they preserve arbitrary entries and inject all current blue keys into one client config. They are not reusable as the participant profile authority or secret store. `loadLabConfig()` validates basic shape, but its unresolved-env warning is not credential-completeness validation. |
| Secrets and generated state | ADR-028/029, `load_dotenv()`, placeholder detection, `EnvVars`, `WebAuthSettings`, `redact()` parity, `curl_safe`, atomic/no-symlink generated writes, ignored state, and restrictive modes own this boundary. Keep the ADR-049 appliance bootstrap parser narrow; do not enlarge `AptlConfig` or `EnvVars` into a workbench secret bag. |
| Browser/API controls | `src/aptl/api/main.py`, `deps.py`, `session.py`, `middleware/bff.py`, the Pydantic response models, and ADR-039/040 own the operator control plane. Reuse their proven Host/origin/session ideas only behind a separate participant gateway; never expose their operator routes. |
| Deployment and Docker authority | `DeploymentBackend`, `DockerComposeBackend`, typed operations, project scoping, bounded argv-list subprocesses, and ADR-013/023/037 own guest Docker. The workbench and profile MCP processes cannot receive a raw socket, Docker CLI authority, generic Docker RPC, or generic command broker. |
| Capture, run association, and evidence | `ScenarioSession`, `trace-context.json`, `RunStorageBackend`, `LocalRunStore`, evidence coordinator/content store, `RangeSnapshot.to_dict()`, ADR-033/041/042/044, MCP `runs.ts`, telemetry, and the capture registry own correlation and storage. Keep MCP-side PTY, Kali-side raw capture, OTel, and SOC evidence distinct. |
| Errors, logging, and readiness | `LabResult`, `StartupOutcome`, `StartupDiagnostic`, deployment errors, ACES `Diagnostic`/operation status, MCP `SSHError` and tool envelopes, `get_logger()`, and OTel telemetry remain the error/observability vocabulary. The workbench adds no appliance-wide exception hierarchy or readiness taxonomy. |

`mcp/aptl-mcp-common/src/captures.ts` is a deliberate incompatibility to
resolve at the existing management/evidence boundary: its current direct
`docker cp` harvest assumes Docker authority next to the MCP process. That
authority cannot be inherited by a participant-serving MCP runtime. Preserve
the existing capture layout and warning semantics through a fixed,
management-owned harvest/evidence operation; do not turn this into a generic
Docker or file-copy API.

## Security And Validation Passage

- **Payload and ingress:** verify the ADR-049 signed appliance identity before
  accepting a seat. The host exposes only the participant endpoint and coarse
  health/recovery channel. The participant gateway validates its bounded
  request/profile shape, authenticates without reusing the operator bearer,
  applies Host/origin/CSRF/WebSocket protections, and returns narrow,
  redacted errors.
- **Profile selection and generated configuration:** accept only the fixed
  profile vocabulary; resolve it through one versioned launcher mapping of
  server identities, non-secret config references, credential aliases, and
  bookmark references. Validate the rendered MCP/client JSON before launch,
  reject missing, empty, malformed, or placeholder selected credentials, and
  verify every referenced server artifact belongs to the released payload.
  Do not duplicate `LabConfig` or accept user-provided executable paths,
  endpoints, environment names, server names, or profile fragments.
- **MCP ingress and transport:** all tool calls still pass each server's JSON
  Schema, handler assertions (including canonical ID validation), endpoint
  origin guard, HTTP timeout/error handling, TLS/CA policy, SSH host/session
  lifecycle, common telemetry, and TypeScript redaction. Generated appliance
  configs must use guest-internal, policy-reachable destinations. Current
  `localhost` assumptions and current `verify_ssl: false` Wazuh/indexer
  settings are not a participant-safe transport contract; no profile may add
  a new TLS-bypass escape hatch.
- **Secret and OS exposure:** model and blue service secrets remain in
  management-only session state and pass only to the selected process through
  a non-argv secret mechanism. Neither profile nor its desktop gets Docker,
  host devices, shared PID namespace, writable host path, source checkout
  secret files, general appliance-management credential, or another profile's
  mount. Inspect process argv, environment/config readability, mounts,
  listeners, packages, and network reachability as separate proof points.
- **Network and browser exposure:** zone policy remains default-deny. Kali has
  no management, participant, blue-control, evidence, Docker, or general
  egress route. Browser bookmarks traverse only declared gateway flows;
  a bookmarked SOC UI is not permission to route Kali to the SOC management
  network or to expose those service ports at the appliance boundary.
- **Persistence, telemetry, and error envelopes:** profile launch, tool use,
  PTY/capture, and teardown use the active run/trace identity from the
  canonical session/runstore path. `_unbound` capture fallback, a new
  workbench-run directory, or a second profile-session ID cannot satisfy the
  association criterion. Redact structured records before persistence or
  telemetry; raw artifacts remain explicitly classified. Errors can expose a
  stable profile/server/validation label, never a token, auth header, provider
  response, command line, raw capture, internal topology, or another profile's
  existence.
- **Teardown and recovery:** selected MCP servers receive their existing
  graceful SIGTERM/OTel/SSH shutdown path before their compartment and session
  secrets are removed. Failure is recorded as a narrow degraded/cleanup
  outcome and blocks reuse of that session; it must not silently leave an old
  blue-capable process alive. Outer guest replacement, not `aptl lab stop -v`
  or `AptlParticipantRuntime.reset()`, restores trust after compromise.

## Extensibility Seam

The one seam is a narrow, versioned profile-launch contract:

`(profile_id, allowed_server_ids, generated_config_refs, credential_aliases,
bookmark_refs, run_id, policy_version)`.

It contains aliases and immutable references, never raw secret values,
arbitrary URLs, Docker targets, ACES topology, or copied MCP `LabConfig`
objects. The launcher resolves it against the signed payload, the admitted
scenario, existing server configuration, and appliance flow policy. The next
reasonable variation, an optional red capability or a read-only defensive
training profile, adds one allowlisted profile entry and its verification
fixture, not another agent implementation, credential schema, browser route
assembly, or copy of the MCP/server contracts.

## Whole-Repository Surface

- ADR-049, ADR-029, ADR-033 through ADR-045, DSL-010, and the existing
  appliance/participant-runtime preflight records.
- `docker-compose.yml`, network/port/mount/capability policy, container
  Dockerfiles, `aptl.json`, `.env.example`, generated `.aptl/` state, and
  appliance payload/launch assets.
- `src/aptl/core/{config,env,credentials,lab,session,runstore,telemetry,
  endpoints,lifecycle_policy,kill}.py`, `core/deployment/`, `core/evidence/`,
  and `backends/aces_participant_runtime.py`.
- `src/aptl/api/`, the Svelte UI and route assemblies, API/web tests, and the
  participant-vs-operator gateway boundary.
- `.mcp.json.example`, `mcp/build-all-mcps.sh`, `mcp/aptl-mcp-common/`, every
  dependent MCP package/config, and their build/test matrix.
- Kali/capture, SOC, OTel, run/evidence, clean-teardown, deployment, workshop,
  recovery, security, and smoke/live validation documentation and tests.

## Verification Guardrails

- Static payload/Compose/container checks prove no physical-host agent or MCP
  process, no participant/workload Docker socket, no forbidden mounts/devices,
  and no participant-reachable operator route or listener.
- Profile unit/integration checks launch each generated profile and assert its
  exact MCP `tools/list` inventory, absent server binaries/config visibility,
  credential-alias separation, failed-closed incomplete secret bootstrap, and
  no cross-profile process survives a switch.
- Network checks prove both allowed profile flows and denied Kali-to-SOC,
  Kali-to-management, participant-to-operator, and workbench-to-Docker paths.
  They must validate live reachability as well as Compose/static declarations.
- End-to-end evidence checks prove agent/MCP/PTY/capture/OTel records share the
  correct existing run/trace identity across red, blue, and purple transitions
  without red-to-SIEM contamination. Teardown tests prove provider/session
  auth and profile state are absent afterward without exporting them.
- Changes under `mcp/aptl-mcp-common` rebuild and test every MCP; Compose,
  Dockerfile, or config changes require the repo's clean-lab validation in
  addition to focused pytest, vitest, web tests, and `pre-commit run --all-files`.

## Gotchas And Anti-Patterns

- Do not reuse the current all-in-one `.mcp.json` or `_sync_mcp_config_keys()`
  for a participant launch. It intentionally preserves arbitrary local client
  entries and combines blue credentials with red capability.
- Do not call a red/blue selector secure when a coding agent can read the other
  config, inspect a shared environment, execute another built MCP entrypoint,
  talk directly to SOC APIs, or issue a generic shell/Docker request.
- Do not put model authentication in Kali, browser local storage, desktop
  profile files, MCP JSON, Compose commands, URL/query data, process argv, or
  a long-lived image/snapshot. `0600` alone is not a serialization boundary.
- Do not expose the existing operator API, web terminal, `kill` process scan,
  or host-facing `ENDPOINT_REGISTRY` URLs through the participant UX. These
  are current developer/operator contracts with broader authority.
- Do not use `docker cp`/Docker CLI from profile MCPs, create a Docker socket
  proxy with arbitrary verbs, or make the capture/runstore volume writable by
  the agent as a workaround for evidence association.
- Do not treat an MCP tool name list, DNS name, Docker network membership,
  loopback bind, CORS, TLS, or a VM as the enforcement boundary by itself.
- Do not create participant/profile copies of ACES DTOs, API types, endpoint
  catalogs, redactors, ID validators, run layouts, tool schemas, error
  classes, readiness states, or workflow engines.

## Non-Goals And Boundaries

- This preflight does not implement the appliance, desktop/browser runtime,
  agent adapter, MCP launcher, profile renderer, gateway, browser bookmarks,
  secret bootstrap, capture mediation, or hosted fleet.
- It does not change the ACES scenario/participant schema, dynamic realization,
  `DeploymentBackend`, existing MCP tool semantics, SOC product configuration,
  operator web control plane, or run/evidence schema.
- It does not grant a participant generic terminal, appliance management,
  direct Docker, arbitrary egress, multi-seat sharing, RBAC/SSO, remote
  operator access, or raw evidence browsing.
- It does not make issue #821 depend on #557's broader participant-runtime
  delivery. It reuses #557's published participant contracts and leaves its
  episode semantics intact while providing the separate in-appliance launch
  and containment seam required for Arsenal delivery.
