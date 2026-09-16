# Issue #992 Backend Observability Ownership Preflight

This note is the architecture preflight for issue #992. It is guidance, not an
implementation plan. ADR-012 owns OpenTelemetry deployment and exposure,
ADR-029 owns secret handling and redaction, ADR-048 owns scenario realization,
ADR-053 owns pack/backend serving, and EXP-010 owns capture admission and
evidence acquisition. The change must join those incumbents without creating a
second topology, capture schema, persistence path, or lifecycle controller.

This note reflects the authorized `raes-env-packs` 6.0.0 / `raes` 4.1.0
TechVault contract set. The earlier
`cortex-job-index-schema-readback` requirement was removed and is not a valid
delivery target. The required set is now `cortex-enrichment-readback`,
`suricata-local-rule-readiness`, `suricata-login-sqli-alert`, and
`redteam-session-transcript`. The repository pins the released pair exactly;
admission work against an old model or fixture is not evidence that this
published contract set is supported.

## Architecture Decisions And Boundaries

### Scope and realized-world reporting

Backend ownership does not exempt observability from RAE open/closed scope
semantics. Closed scopes must not gain undeclared agents, services, network
attachments, or other changes to the scenario's in-principle visible world.
Prefer capture that can satisfy every SDL evidence requirement without such
changes. Within an open scope, choose the least intrusive supported option
that genuinely meets every required evidence term; permission to add a
component does not establish its necessity. Existing native readback takes
precedence over an added agent or stack whenever it meets the entire need.
Closed scopes exclude intrusive options altogether; do not weaken evidence
requirements to make an option fit. Report every component added specifically for
observability in the realized-world report to the runtime, including additions
the SDL did not request; do not report only the requested realization. Reject
admission when any required evidence cannot be collected within these bounds.
The public RAE models and conformance rules determine the reporting and scope
boundaries; an APTL label such as "backend apparatus" cannot bypass them.
`raes_observation.observe_realization()` currently enumerates planned resources;
it is not an inventory of all added apparatus. Reuse the RAES observation and
realization-envelope boundary for truthful disclosure, with native runtime
inventory as evidence. Do not forge authored addresses to hide that gap.

TechVault's four 6.0.0 contracts have native owners: Cortex/TheHive APIs,
Suricata's realized configuration and EVE output, the Wazuh index, and the
existing red-workstation session/capture boundary. None depends on OTLP or
Tempo. Therefore the admitted TechVault plan must omit Collector, Tempo, and
Grafana in open as well as closed scopes. TechVault's host-root-equivalent
Docker authority could enumerate same-daemon apparatus even on a private
network, so an isolated Compose network would not make that addition
non-intrusive. Report the absent operator view as a limitation of the realized
apparatus, not as evidence loss.

### Keep three concepts separate

| Concept | Owner and meaning |
|---|---|
| Scenario evidence intent | RAES `evidence_requirements` describes what must be observed and the required policy semantics. It neither selects a container nor proves capture. |
| Backend apparatus | APTL owns Collector, Tempo, Grafana, their configuration, private storage, network attachment, host publication, readiness, and cleanup. These services are not RAES scenario nodes. |
| Admitted evidence | The existing `CollectorRegistry` matches a public RAES experiment capture contract to a trusted `CaptureBinding`; the evidence coordinator performs acquisition, redaction, loss classification, and `LocalRunStore` persistence. |

An available OTel stack is a prerequisite for the Tempo trace source, not a
universal answer to evidence requirements. In particular, an `api_response`
requirement must bind to a collector that honestly supports that channel; it
must not be relabelled `workflow-history` because Tempo happens to be running.
Where scenario intent is referenced by an experiment capture contract, retain
the RAES reference and model boundaries. If no supported normative binding
exists, admission fails closed rather than introducing an APTL copy of the
schema or a lossy field mapping. That rejection is a guardrail, not completion
of #992: the supplied TechVault requirement must actually be supported.

RAES 4.1 owns the intent-to-demand boundary through
`compile_scenario_capture_demands()`. APTL consumes those normalized public
demands directly and matches them to exact trusted offers; it does not require
the SDL to name a separately authored capture spec and does not synthesize an
`ExperimentCaptureSpecModel` in the backend. Admission requires semantic
agreement on source/channel, scope, window, format, sensitivity, redaction,
integrity, retention, and loss disclosure. Preserve `source_refs`,
`scope_refs`, `channel_refs`, `trigger_ref`, and boundary references in the
admitted binding/provenance rather than flattening them into notes. A broad
registration can otherwise overclaim a semantically different channel. The
trusted registration needs an exact semantic channel/source selector, while
the manifest remains only an aggregate capability projection. Do not cast
between models, use `model_copy` to bypass validation, or infer coverage from
that aggregate.

The versioned capture-plan obligation is already owned by ADR-047's
`TrialPlan`, `canonicalize_trial_plan()`, and admission `_persist_plan()`
boundary. Reuse its immutable `CaptureBinding` projection, RFC 8785 identity,
create-once persistence, and post-write digest verification. A direct-scenario
entry point must not introduce a parallel `ScenarioCapturePlan` or pretend a
persisted `ExperimentCaptureSpecModel` is the admitted plan. If a full
`TrialPlan` cannot be created without a fake experiment/run plan, factor its
capture sub-projection into one canonical, versioned core capture-plan value
that `TrialPlan` embeds and direct-scenario admission reuses. There remains one
plan schema/identity/persistence owner. Any such projection change requires a
schema-version bump; old bytes must never acquire new meaning. The plan pins the
exact references, bindings, limits, and accepted limitation/comparability
disclosures before any build, pull, probe, or realization mutation.

### Contract-specific source boundaries

The four contracts are not variants of one generic "observability" collector.
Each registration must claim only the exact semantic source it implements.

| Required contract | Source boundary and admission proof |
|---|---|
| `cortex-enrichment-readback` | One composite, bounded native-API outcome must prove the exact enabled analyzer identity, a successful `TechVaultScenarioContext_1_0` report for `172.20.1.30`, and TheHive's Cortex connector status in the same admitted window. All three are required; a Cortex job acknowledgement, generic health response, or TheHive connectivity alone is not coverage. Project only the allowlisted fields needed by the contract into `application/json`; do not retain whole API responses. Reuse the SOC transport/CA and `curl_safe` boundaries. |
| `suricata-local-rule-readiness` | Join admitted source identities from `DetectionContentProvider`, the realized Suricata image identity from the owner-supplied `RangeSnapshot`/`RuntimeFactsProvider`, and a post-start engine-native readback of configuration success, selected rule sources, realized in-container byte digests, and exactly all 16 loaded local SIDs. Source-file presence or parsing `local.rules` does not prove loaded state. The `text/plain` projection contains identities, digests, status, source labels, counts, and SIDs only—never rule bodies, host paths, or container paths. |
| `suricata-login-sqli-alert` | Drive one fresh, participant-equivalent Kali `POST /login` containing the required `UNION SELECT` stimulus, then produce a deterministic `application/x-ndjson` projection containing both Suricata SID `1000010` and Wazuh rule `303020` from the same bounded window and correlation. The join must use source/target/flow or source-event lineage, not timestamp proximity alone. Historical hits, the existing GET-based live-gate stimulus, Wazuh rule `302010`, or either source alone are not coverage. Reuse the bounded trigger/poll/deadline patterns from `_live_gate_operations.py` and `_live_gate_telemetry.py`, but do not persist their verification-report DTO as evidence. Record the synthetic trigger as an observer effect so it cannot be mistaken for participant behavior. |
| `redteam-session-transcript` | Reuse ADR-041's isolated sidecar storage/harvest and ADR-042's sidecar-owned PTY-master boundary, plus the existing MCP `PersistentSession` and MCP-side tee as the independent cross-check. Admission requires a complete session census, attributable command/input and response/output ordering, sequence/gap/clock/close metadata, and final quiescent harvest from readiness through teardown. Current workload-fed `script(1)`/FIFO capture is explicitly non-conformant with ADR-042, MCP capture is output-only and best-effort, and `aptl container shell` bypasses SSH `ForceCommand`; until every interactive ingress is routed through or prohibited by the admitted capture boundary, this required contract must reject. A checksum without that custody path does not satisfy `chain_of_custody`. |

The collector coordinator must start each source before its declared window,
keep full-run sources alive across readiness, participant actions, runtime
workflows, and normal teardown, then stop in reverse order and finalize only
after source quiescence. Wrapping only `DeploymentBackend.realize()` omits most
of the transcript window. Forced kill and TTL teardown remain prompt but must
produce terminal loss/finalization outcomes; capture must not become a second
lifecycle state machine.

### One backend apparatus definition, included only when admitted

There must be one project-owned Compose definition for the three services and
their volumes. `DockerComposeBackend` adds it to the existing effective Compose
file set for static and generated scenario bases only when the immutable
admitted apparatus selection includes OTel. Knowing the asset exists, an
operator profile toggle, and the legacy `CORE_PROFILES` tuple are not scope or
capture admission. The trusted APTL project root supplies config bind sources;
paths must never be resolved from an immutable pack root or supplied through
pack content.

`render_realization_compose()` remains solely a projection of
`DeploymentRealizationSpec`. Do not add synthetic OTel
`DeploymentNodeRealization` objects or mutate the admitted RAES plan/snapshot
to make backend services appear scenario-authored. Selected backend apparatus
must also start for an all-image-free scenario, so the current
scenario-node-only `_needs_compose()` decision cannot be the authority for
apparatus lifecycle.
Stop, kill, clean, and lifecycle-policy enforcement retain scenario-independent
runtime discovery in `_compose_stop.py` / `_compose_lifecycle.py`. They must
work after pack/generated files disappear. Containers and networks use project
labels; `_compose_volume_cleanup.py` also uses the validated project-name
prefix for volumes created before Compose can label them. Preserve that
incumbent distinction; do not add global prune or name-only container deletion.

Runtime parity and readiness need two explicit sets: admitted scenario
resources and code-owned backend apparatus. The three established service
identities are reserved to the latter. A pack or in-tree SDL that still claims
one is an incompatible duplicate and must fail with a bounded diagnostic; it
must not be silently preferred, merged, or counted as a scenario resource.
Check native container names, network/volume keys, and mount destinations as
well as service keys before Compose merge can conceal a collision.

Do not transplant `aptl-security` or its fixed `172.20.0.*` addresses as a
requirement on every pack. Keep apparatus on backend-owned networking, with
only admitted producer access. Any attachment to an exercise network crosses
RAES topology, runtime-listener/forwarding-agent observation, ACL and range
egress gates. Host loopback binding does not isolate containers sharing a
network; an extra interface must not bypass target containment. No Docker
socket, privileged mode, or additional host mount is needed by these services.

### Operator surface remains local and deliberate

The accepted ADR-012 surface remains:

- Grafana UI on loopback, default host port `3100`, with the live remapped URL
  printed only when Docker reports a real binding;
- Collector OTLP/gRPC and OTLP/HTTP on loopback, default ports `4317` and
  `4318`, for host-side producers; and
- Tempo HTTP on loopback, default port `3200`, for the host-side trace source.

Reuse the existing `${APTL_HP_*}` declarations, host-port resolver, live Docker
port reconstruction, and `.env`-generated Grafana password. No observability
host publication binds to `0.0.0.0`; container receiver listeners are a separate
scope. Tempo and Collector have no host authentication, so a
remote/shared surface requires a separate authenticated network design and is
not an option hidden behind a port change.

Loopback publication is reachability restriction, not producer authentication.
Any local process able to reach OTLP can submit data, and the current
Collector-to-Tempo hop is unauthenticated. Therefore this topology cannot claim
signed origin, chain of custody, or exclusive-producer integrity. Preserve the
registry's existing `supports_chain_of_custody=False` and digest-only integrity
claim; a requirement that needs stronger source authenticity fails admission.
For requirements this topology can admit, bind records to the exact run,
attempt, source window, collector/config identity and observed loss state, and
record the unauthenticated transport as a comparability/provenance limitation
where it is material. A random or shared trace ID is correlation, not proof of
who produced a span.

Resolve endpoints for consumers as well as the CLI: Python and TypeScript
currently default `OTEL_EXPORTER_OTLP_ENDPOINT` to `localhost:4318`, and
`collect_traces()` defaults `TEMPO_URL` to `localhost:3200`. A remapped port
must reach those clients. Host, container and Docker-daemon loopback are
different addresses; use the existing endpoint/runtime-inventory boundary
and trusted launch environment. Reject unsupported remote artifact/reachability
cases through `supports_local_artifacts` and existing backend diagnostics.
An SSH Docker connection does not itself forward the telemetry ports.
Tempo's base URL remains backend-owned and the trace/run identifiers appended
to it must pass their canonical bounded validators before request construction;
scenario text and capture references never become a URL, header, query fragment,
or redirect authority. Do not let a generic HTTP client follow this source seam
away from the admitted local endpoint.

The extensibility seam is an immutable admitted apparatus set that derives the
backend-owned effective Compose file set and existing host-port parameters;
the capture-side seam remains `(CaptureBinding, registration_id, trusted source
adapter)`. A future store or operator view changes behind those seams. It does
not add scenario nodes, a pack-controlled image/URL/path, or a second
profile/config vocabulary. Select OTel only when an admitted binding depends on
its Tempo/OTLP source, or under a separately authorized operator-only mode that
is reported as actual apparatus. The scope decision, apparatus set, endpoints,
and effective file set are immutable request-scoped inputs to realization,
readiness, observation, and teardown. Do not communicate them through an ad hoc
private attribute on a reusable backend: retries, concurrent admissions, and a
later scenario can otherwise inherit stale authority.

### Evidence promises are enforced above the containers

- Redaction reuses `src/aptl/utils/redaction.py`, the common TypeScript
  redactor, and the coordinator persistence boundary. Python OTel attributes
  must cross the same policy boundary as TypeScript attributes. Do not rely on
  every caller remembering to sanitize a span. Include events, exception
  attributes, resources, nested serialized tool data, and endpoint URLs.
  `APTL_EXPERIMENT_NO_REDACT` never disables shared OTel/store redaction.
  `get_logger()` has no automatic redaction filter: sanitize before logging.
  Malformed JSON must never pass through as unredacted structured evidence;
  opaque bytes and multi-record JSONL also need honest format-aware treatment.
  Required redaction must reject unsupported/malformed payloads before export
  or persistence, never retain them raw and call the policy satisfied.
- `redact_sensitive` and `redact_secrets` are distinct authored policies, not
  one `redaction_required` boolean. Reuse one trusted policy-to-handler map at
  the coordinator persistence boundary; do not add per-collector redactors or
  silently apply the weaker policy. `_persist.py` currently rejects required
  redaction for `text/plain`, so the transcript/readiness contracts cannot be
  registered until a bounded, streaming-safe text projection/redaction path
  exists. It must handle secrets split across chunks and redact before the
  first CAS, ordinary run-archive, or export write. A raw source spool may
  exist only inside the authorized isolated capture boundary and must be
  destroyed after safe handoff according to the admitted retention policy.
- The Collector's default `debug` exporter is not an evidence sink and must
  not duplicate trace payloads into container logs. Logs contain bounded
  identifiers, stages, codes, counts, and durations only.
- Tempo's current 72-hour TTL is a default query-buffer policy, not the meaning
  of `run_lifetime`. Define the authored policy's lifetime anchor, minimum
  availability and any deletion deadline using RAES semantics. Apply it to
  every retained copy, including queues, WAL/blocks, logs and exports; a cache
  label does not exempt bytes from a deletion obligation. Canonical evidence
  stays under `LocalRunStore` and ADR-050 sealing. Neither the registry's
  boolean `supports_retention` nor the store currently implements arbitrary
  policy enforcement. Lab TTL, `stop -v`, run completion and archive expiration
  are distinct. Preserve per-run finalization locks and seal immutability;
  never expire individual blobs out of an otherwise valid sealed archive or
  delete another run's evidence to implement a per-run policy.
- `loss_disclosure: required` needs an observable result. A live pipeline must
  distinguish Collector/Tempo unavailable, exporter/drop loss, a successful
  empty trace, truncation, timeout, and finalization failure. The current
  `collect_traces()` empty-on-error behavior is not a conformant source result.
  Use `SourceResult` / `CollectorStatus`; unknown upstream loss cannot be
  reported as zero drops. SDK sampling, queue overflow, retry exhaustion,
  exporter shutdown and Tempo indexing delay all affect completeness.
- The same rule applies to native sources. A missing Cortex sub-proof, malformed
  Suricata line, incomplete Wazuh page, open transcript session, missing
  sequence, failed harvest, or unknown drop count is a typed loss/failure, not
  a successful empty result. The legacy `collectors.py` APIs intentionally
  collapse failures to empty lists; adapters may reuse their parsing/query
  knowledge but not that return contract. Composite contracts succeed only
  when every required component is present and correlated.
- Readiness is not `docker ps` or `otelcol validate`. It must establish a live
  Collector-to-Tempo path before a dependent capture window opens. Collector
  and Tempo remain alive during normal acquisition finalization, including
  producer flush and bounded read-after-export. Forced kill/TTL teardown must
  remain prompt and disclose interruption/loss through the existing executor
  and archival workflow; evidence finalization cannot disable the kill switch.
- Grafana is optional to capture correctness. The local operator-surface
  decision is subordinate to closure and minimum intrusion; report its
  omission when scope-preserving selection excludes the stack. Its health or
  absence never changes an evidence result into success.
- Reuse `RunScope`, `ClockProvider`, correlation identities, evidence visibility
  projection and `backend_evidence` provenance. Pin apparatus image/config and
  collector policy identities without recording secrets. Reuse
  `RuntimeFactsProvider` and the owner's redacted `RangeSnapshot` projection for
  realized image digests rather than re-inspecting Docker in a collector or
  provenance provider. Scope queries to the exact run/attempt and source window;
  a shared Tempo store, timestamp proximity or the shared
  `.aptl/trace-context.json` file is not proof of run identity.
- Inject a narrow, attempt-scoped receipt/source provider into a collector.
  Never hand it the deployment backend or publish receipts by dynamically
  attaching a mutable mapping to that backend. Native realization and runtime
  owners return typed, immutable receipts keyed by admitted source identity;
  clearing ambient state is not isolation. The collector must not become a
  second Docker inspector, workflow verifier, HTTP client policy owner, or
  arbitrary container-exec surface.
- Participant-hidden and secret-bearing evidence stays inaccessible at every
  projection, not merely labelled as hidden in its record. Keep Grafana and
  Tempo out of participant endpoint/credential projections; reuse evidence
  visibility filtering in run references, bundle export and any future API.
  An operator login authorizes the local operator view, not participant access
  or publication of raw payloads.
- Retain Compose resource limits and bound ingestion, retries, queues, disk and
  log growth. `CaptureLimits` is the existing capture budget. Enforce limits
  before HTTP decode/JSON joins as well as during persistence. Limits are
  registration-specific: the current shared five-minute/eight-MiB defaults
  cannot truthfully describe an otherwise valid full-run transcript. A
  full-window deadline is still bounded by the admitted attempt/lifecycle and
  must not become either an arbitrary five-minute truncation or an unbounded
  collector call.

### Required extensibility seams

- **Plan:** one canonical capture-plan sub-projection, embedded by `TrialPlan`
  and reused by direct-scenario admission; parameterized by public artifact
  identities, immutable bindings, policy version, and disclosures.
- **Source:** the existing registration-ID-to-trusted-adapter composition seam;
  parameterized by an immutable binding, run/attempt/window, limits, clock, and
  narrow source-specific settings/receipts. Do not parameterize executable,
  URL, path, credential-name, or import selection from RAES input.
- **Policy:** one code-owned mapping from the admitted redaction/retention
  vocabulary to trusted handlers. New policy terms extend this map and its
  conformance tests rather than adding collector-local booleans.
- **Sessions:** ADR-042's sidecar session-launch adapter and recorder metadata
  version, with one ingress registry/session census. Another interactive
  frontend must register with that owner or be unavailable during required
  capture; it must not add a parallel transcript or harvester.
- **Apparatus:** the immutable admitted apparatus set derives effective Compose
  files, endpoints, readiness, observation, and cleanup. A future store or UI
  changes behind that seam without changing scenario topology.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical incumbent and required use |
|---|---|
| RAES shape and admission | Public `raes_contracts` models/loaders, `src/aptl/core/experiment/admission.py`, `capture_mapping.py`, `capture_registry.py`, immutable `CaptureBinding`, and ADR-047 canonical plan persistence. Do not duplicate evidence schemas, scenario mappings, plan identity, or matching logic. |
| Capture lifecycle and errors | `src/aptl/core/evidence/coordinator.py`, `_persist.py`, `records.py`, `visibility.py`, `outcomes.py`, trusted adapters in `adapters/`, and RAES `Diagnostic`. Preserve public `experiment-evidence-record-v1` construction plus typed source-unavailable/startup/loss/truncation/timeout/finalization outcomes; do not add a second record schema or exception hierarchy. |
| Persistence and terminal ownership | `RunStorageBackend`/`LocalRunStore`, content-addressed evidence, create-once ledger, `ExperimentExecutor`, and `archival.finalize_terminal_attempt` / `verify_sealed_archive`. Reuse path containment, no-follow writes, per-run locks, terminal-cause normalization and seal verification. `RuntimeFactsProvider` consumes the owner's redacted `RangeSnapshot` for realized image identities; it is not a second Docker inspector. |
| Cortex/TheHive evidence | Existing SOC endpoint ownership, lab CA/TLS rules, `curl_safe`, TheHive/Cortex seed/config owners, and bounded collector timeouts. Add a narrow typed composite source; do not reuse provisioning shell scripts as runtime collectors, expose a generic API/exec client, or pass bearer material in URLs/argv. |
| Suricata evidence | `DetectionContentProvider`, `NamedVolumeSeed`/`suricata_seed.py`, `SuricataReloader`, owner-supplied `RangeSnapshot`/`RuntimeFactsProvider`, `collect_suricata_eve()` parsing knowledge, and the bounded live-gate trigger/poll pattern. Keep authored/source identity, realized-byte identity, engine-loaded state, and emitted alert state distinct. |
| Red-session evidence | ADR-033/041/042, `PersistentSession`, common MCP `runs.ts`/`captures.ts`, the sidecar-owned capture volume/harvest path, CLI container-shell and web terminal ingress, canonical run/session ID validation, and the existing MCP error envelopes. One session census/custody boundary must cover every ingress; do not add a second harvester or session vocabulary. |
| Scenario realization | `ScenarioBundle`, RAES parse/compile/plan, `DeploymentRealizationSpec`, `base_compose_file()`, `_realization_compose_files()`, and effective model validation. Backend apparatus is an additional trusted file-set input, not realization DTO data. |
| Configuration and secrets | Strict `AptlConfig`, `ContainerSettings`, `env.py` hydration/required-value checks, `contains_placeholder`, ADR-029, and shared redactors. Reuse `GRAFANA_ADMIN_PASSWORD`; pack data cannot configure apparatus env keys, credentials, mounts, images or endpoints. `EnvVars` remains the existing Wazuh credential DTO; any Cortex/TheHive source settings are a narrow validated composition input, not fields smuggled into that DTO or read by collectors from ambient env. |
| Native ownership and lifecycle | Validated Compose project name, Compose labels, lifecycle lock, `stop_lab`/kill/clean, and project-scoped cleanup. Never replace or delete a same-named foreign resource. |
| Ports and operator rendering | `src/aptl/core/host_ports.py` and `src/aptl/cli/lab_render.py` live-state rendering. Parameterize their input over the canonical file set rather than adding an OTel-only port parser or hard-coded URL. |
| Process, HTTP, logging | Argument-vector Compose execution, existing runners/timeouts, `curl_safe`, `get_logger`, safe `LabResult`/`ApplyResult` projections, and bounded diagnostics. No shell construction or raw stderr/response/telemetry payload in logs. |
| Distribution and release | `_asset_manifest.py`, `hatch_build.py`, `core/assets.py` and `aptl lab init` own packaged assets; `pyproject.toml`, `uv.lock`, every hashed requirements file, namespace/pin tests, and the TechVault serving map/digest own the RAES/env-pack compatibility set. A new top-level Compose file must be bundled, materialized and visible to the daemon, including appliance/web-driven starts. |
| Image and offline policy | Code-owned exact image references, `_docker_image_identity.py`, existing offline staging/start behavior, and `RangeSnapshot` own image trust and realized identity. Pack input cannot select apparatus images; record the daemon-resolved digest, and do not mistake an allowed repository name or mutable tag for the realized artifact identity. |
| Repository governance | `.ground-control.yaml` trust-boundary paths, `.gc/plan-rules.md`, `.github/workflows/checks.yml`, the README/scenario catalog and in-tree compatibility SDLs are consumers of the ownership cutover. Keep the observability/host boundary map aware of a new top-level Compose asset plus backend/evidence adapters, and keep the installed-wheel clean-start gate aware of the separate file. Retire scenario-owned OTel fixtures and obsolete schema-readback tests in the coordinated cutover. |

## Security And Validation Passage

| Layer | Required passage |
|---|---|
| Pack ingress | Bundle staging, digest/containment validation, public RAES parsing and compilation remain authoritative. A pack supplies evidence intent and scenario topology only. |
| Capture admission | Resolve public capture references through the existing bounded artifact resolver, validate both public models and their exact semantic join, then use the canonical registry/policy and plan-persistence boundary. Unsupported source/channel identity, scope/ref, window/boundary, media, sensitivity, redaction, integrity, retention, or loss semantics reject before capture-dependent execution; current aggregate/boolean checks are insufficient. Required degradation is forbidden; optional degradation needs `CaptureLimitationAcceptance` plus a pinned comparability disclosure. |
| Native source/result shape | Each trusted adapter uses an allowlisted endpoint/container/source, strict bounded JSON/NDJSON/text parsing, response-size and pagination limits, timestamp/window checks, and an allowlisted portable projection. Composite Cortex and Suricata/Wazuh results validate all required members and exact identities before success. Malformed, partial, stale, duplicate, or uncorrelated input becomes a typed failure/loss result; it is never passed through raw or interpreted as empty success. |
| Config and env shape | Durable non-secret settings pass strict `AptlConfig`. Grafana env values use `hydrate_dotenv`, `validate_required_env` and `find_placeholder_env_values`, not an overloaded `EnvVars`. `GRAFANA_ADMIN_PASSWORD` must be nonempty and non-placeholder even on lower-level startup paths; the placeholder check alone permits absence. Cortex/TheHive/Wazuh source credentials are loaded once at trusted composition into narrow immutable settings, validated with the incumbent required/placeholder/port/URL/CA rules, and never selected through scenario fields or read from ambient env by a collector. |
| Compose model and binds | Explicit `-f` assembly, `_check_bind_mounts`, syntax checks, `effective_stateful_model_errors` and `effective_orchestration_model_errors` see the combined effective model. Today some paths inspect only one static file or skip validation without scenario stateful content. Bind paths come from the trusted project root, exist as the expected file type, remain read-only and are visible to the daemon. Preserve explicit operator `--env-file` binding against pack `.env` shadowing. |
| Image and artifact identity | Apparatus image names and versions are fixed by trusted backend assets, remain compatible with offline staging, and are observed after start through the existing runtime snapshot/digest path. Scenario/pack fields never become image references, pull credentials or registry authorities. |
| OS/network/process exposure | Commands remain fixed code-owned argv arrays with bounded output/time; no shell construction. The SQLi trigger may supply only the admitted Kali origin, fixed target endpoint, and contract payload—never a host command or scenario-chosen URL. Publications are loopback-only and collision-remapped through existing host-port policy; native resources are project/label scoped. The transcript sink stays outside Kali's mount/PID authority, and every interactive ingress, including CLI Docker exec and the web SSH terminal, is either routed through the one admitted PTY owner or disabled for the capture window. |
| Auth and secret carriers | Grafana uses its own login, signup disabled, with generated credentials; it does not inherit APTL API authentication. No anonymous view or embedded credentials in URLs/argv. Preserve credential continuity with its persistent data volume; generating a new `.env` is not proof that an existing database's password changed. `curl_safe` owns sensitive HTTP header/body carriers and logs no secret-bearing URL. Cortex's accepted internal HTTP constraint does not remove bearer authentication; TheHive continues through the lab-CA/TLS policy. OTLP/Tempo have no authentication, so loopback is only a local reachability boundary and must not be represented as producer authenticity. No new API route is needed; any status projection uses `WebAuthSettings`, `verify_token`, `BFFMiddleware` Host/CSRF/Origin gates and existing API response models. |
| Producer launch shape | If endpoint propagation touches managed MCP launches, preserve `workbench/agent.py`'s private-file checks, exact `command`/`args`/string-valued `env` shape, credential-alias resolution and configuration digest recheck. Its `_server_environment` does not inherit arbitrary controller env. Resolve non-secret endpoints before launch/admission; do not rewrite admitted configs or inject credentials into arguments. |
| Request-state isolation | The admitted scope decision, capture bindings, source receipts, endpoint map and effective Compose files travel as typed inputs scoped to one run/attempt. A singleton/reused backend, module global or process environment must not carry per-admission authority or evidence state across retries or concurrent starts. |
| Error envelope | Normalize Compose, readiness, source, query, trigger, session, harvest, and finalization failures into existing `LabResult`, `ApplyResult`, `StartupDiagnostic`, RAES `Diagnostic`, MCP `SSHError`/tool results, and collector outcome shapes. Redact before projection; never return raw Compose config, command lines, transcript bytes, HTTP bodies, or source stderr. Preserve legitimate empty as distinct from unavailable/incomplete. |
| Telemetry/evidence | Apply the exact `redact_sensitive` or `redact_secrets` handler before any retained copy, bound payloads and pagination, hash retained bytes, record clocks/source pipeline/observer effect/redaction and all loss, and enforce `run_lifetime` for CAS blobs plus temporary/sidecar/MCP/source copies. Validate canonical run/attempt/session identifiers at every language/process boundary. Enforce `CaptureVisibility` again at run-reference, bundle-export, API, Grafana/Tempo, and participant projections; a hidden label is not an access-control boundary. |

## Compatibility Cutover Guardrail

OpenRAE/env-packs#338 has merged. `raes-env-packs==6.0.0` removes the three
observability nodes and the obsolete schema-readback requirement and carries
the four contracts above; it moves atomically with `raes==4.1.0`,
`pyproject.toml`, `uv.lock`, every hashed requirements file, namespace/pin tests,
the TechVault serving map and qualified pack digest, and in-tree catalog/
compatibility fixtures. The exact 6.0.0 artifacts, not a hand-rewritten local
copy, are the conformance input. The observability-only scenario must not survive
as three phantom backend nodes; retire it unless it has independent exercise
semantics.

Do not add pack-version branches, retain old requirement-ID special cases,
tolerate both topology owners, or silently discard duplicates. Tests and
live-range parity must classify backend apparatus separately so removing pack
nodes cannot make capture disappear and adding backend services cannot make
them look like unexpected scenario topology.

RAES 4.1 still chooses `guest-observed` for runtime configuration concerns
whose author did not select an evidence location. Until OpenRAE/rae#1285 is
released, APTL carries a temporary compatibility layer tracked for removal by
APTL #1017. It is limited to the content-identified TechVault 0.1.0 release: it
marks compiler-generated open concerns APTL does not realize as delegated so
RAES resolves them through its closed apparatus default, changes the observation
floor only for concern families with a complete APTL readback, and leaves every
unsupported authored demand unchanged so admission still fails. The resolved
authority inventory therefore records the no-addition decision without
rewriting the author's governing open scope or fabricating absence evidence.

RAES 4.1's complete authority expansion makes the released 124-resource plan
cost 87,526 nodes under its portable-value traversal, above the generic 65,536
node ceiling. The same exact-release compatibility boundary temporarily raises
only that node ceiling to 131,072 while RAES applies the plan; depth, members,
operations, scalar size and total scalar size remain unchanged, and the
original process-global values are restored even on failure. Unknown pack
identity, version or set digest receives no override. This is a bounded release
workaround tracked for deletion by APTL #1017, not a general permission to
disable or dynamically size RAES input validation.

The RAES apply result detail carrier is separately bounded. If the diagnostic
projection of a large realization would exceed that carrier, APTL returns
resource identities and counts there while the complete observed realization
remains in the runtime snapshot. Every added capture apparatus record remains
present in both the compact detail projection and its addressed snapshot entry;
size reduction never drops an observability addition.

For structured configuration that Docker does not expose directly, the bridge
uses a content-addressed release attestation rather than adding an in-world
inventory agent. Each disclosed node/concern projection is independently
digest-pinned and additionally requires the exact realized immutable image or
all targeted exact content placements. An unknown release, changed projection,
missing placement observation, or different image discloses nothing. Direct
daemon/guest readback remains authoritative where available. This bridge is not
a general evidence model and must be deleted, not broadened, once the upstream
contract can express an unconstrained observation method.

Compose has no service-level `--rm`. For an authored
`container.autoremove: true` one-shot node, APTL first observes exit zero,
captures the bounded daemon/image/OS evidence needed by the runtime gate,
removes the exact project-owned container, verifies absence, and carries that
receipt in a typed per-apply context through observation. Failure to capture,
remove, or verify fails realization. The reusable backend stores no receipt, so
a retry or later scenario cannot inherit evidence from an earlier apply.

## Verification Boundaries

Use the existing tests, not a second validation harness. Ownership and lifecycle
coverage belongs with `test_env_pack_realization`, mixed/image-free realization,
scenario-bundle roots, Compose cleanup, lifecycle guards and pack-interaction
tests. Prove operation with a pack containing zero observability nodes and
prove TechVault selects no OTel apparatus. Separately prove an independently
authorized OTel selection works without `aptl-security`; prove duplicate
ownership rejects before mutation and closed-scope additions fail while
permitted additions are disclosed.

The evidence oracle is the authored requirement joined to an actual retained
record and its outcome. Exercise the exact analyzer/report/connector triple;
all 16 engine-loaded SIDs plus admitted/realized identities and absence of rule
bodies/paths; a fresh POST producing correlated SID `1000010` and Wazuh rule
`303020`; and every shell ingress from readiness through teardown with custody,
ordering, attribution, gap, redaction, and final-harvest checks. Negative tests
cover one missing composite member, historical/uncorrelated alerts, the legacy
GET/`302010` pair, direct Docker-exec bypass, workload transcript forgery,
unclosed sessions, source outage, partial pagination, malformed NDJSON,
chunk-split text secrets, oversize/truncation, retention cleanup, hidden-data
projection, and forced teardown. Extend the existing registry/mapping,
evidence security/coordinator/correlation, MCP common, sidecar, provenance,
live-gate, and archival suites; do not create a separate #992 harness.

Run `pre-commit run --all-files`, the configured completion checks in
`.ground-control.yaml`, and relevant static/live RAES gates. Common TypeScript
changes require every dependent MCP to rebuild and pass tests. Compose/config
changes require the clean fresh-machine lab gate in `.gc/plan-rules.md`, with
the exact 6.0.0 native evidence oracles. If the optional OTel asset changes,
also prove real ingestion, retrieval, operator login and teardown in a
separately admitted mode. A successful Compose config parse, mocked query or
historical range snapshot cannot replace that gate. Documentation uses Vale and
`mkdocs build --strict`.

## Gotchas And Anti-Patterns

- `CORE_PROFILES = ("otel",)` is legacy unconditional selection and conflicts
  with ADR-012's updated admission rule. It cannot remain the authority that
  activates apparatus, and selecting a profile cannot create services absent
  from the effective Compose model.
- Any old RAES/env-pack pins and old
  schema-readback fixtures are incompatible inputs, not a fallback mode.
- The generic built-in registrations only promise JSON, `redact_secrets`,
  digest integrity, and short run/task/interval windows. Do not widen them on
  paper to admit `text/plain`, NDJSON, `redact_sensitive`, composite source
  semantics, or chain of custody. Add only exact registrations backed by exact
  adapters and conformance tests.
- Starting capture around realization alone misses readiness, actions,
  workflows, and teardown. A full-run transcript cannot be reconstructed after
  the fact from whatever files happen to remain.
- `aptl container shell` uses direct Docker exec, the web terminal has its own
  SSH client, and current Kali `script(1)` feeds the sidecar from the workload.
  Counting only MCP `PersistentSession` calls neither covers every shell nor
  meets ADR-042 custody.
- A terminal byte stream is not automatically an attributable command log.
  Do not infer commands by naively stripping ANSI/terminal control sequences;
  preserve direction, session principal, ordered input/output and lifecycle
  metadata, and make any higher-level command projection explicit and tested.
- The current structured persistence path cannot safely redact required
  `text/plain`; visibility=`withheld` does not make an unredacted stored copy
  safe, and checksums do not repair that boundary.
- Relative config mounts can resolve against an env-pack project directory.
  Backend config paths must come from the trusted APTL project root.
- All-image-free realization currently bypasses Compose, while apparatus still
  needs Compose. Do not couple apparatus activation to image-backed nodes.
- Do not equate container health, a registry declaration, a Tempo query, or a
  Grafana screen with satisfied evidence.
- Permanent fail-closed rejection is not delivery of the four MUST contracts.
  Rejection is correct only until every exact source and policy term has an
  admitted, exercised implementation.
- Do not treat 72 hours as `run_lifetime`, failure as an empty result, or SDK
  best effort as compliant loss disclosure.
- Do not add an OTel DTO, evidence repository, port resolver, exception tree,
  logging policy, lifecycle state machine, or pack-specific orchestration
  branch beside the incumbents above.
- Do not add a scenario-specific capture-plan DTO, persist only the source
  capture spec, or place typed SDL intent into free-text notes as a substitute
  for the canonical versioned plan and semantic reference.
- Do not use mutable private backend attributes as request context, scope
  authorization, collector wiring, or a receipt ledger.
- Do not expose raw trace payloads through the Collector debug exporter,
  Compose stderr, CLI/API diagnostics, or unredacted Python span attributes.
- Do not treat loopback OTLP, a trace ID, a retained-byte checksum, or a
  Collector registration as producer authentication or chain of custody.
- Do not persist raw Cortex/TheHive responses, Suricata rule bodies or paths,
  full Wazuh/Suricata events, shell command lines, transcript bytes, or source
  stderr in diagnostics, logs, telemetry, ordinary run archives, or participant
  projections merely because a later redactor exists. Raw source spools stay
  inside the authorized isolated capture boundary and are retention-governed.

## Non-Goals

- A remote, multi-user, internet-exposed, or highly available observability
  platform.
- A generic operator-dashboard plugin system or replacement for Grafana.
- A redesign of RAES scenario/evidence schemas, the experiment controller, or
  the collector registry beyond the one exact semantic-selector/canonical-plan
  seam needed to reuse their existing responsibilities.
- A second scenario-only planning or persistence model beside ADR-047's
  canonical trial/capture-plan boundary.
- Universal capture of every evidence channel through OpenTelemetry; each
  requirement still needs an honest matching source adapter.
- Activating OTel for the four TechVault 6.0.0 contracts, or treating the
  availability of an operator dashboard as a capture requirement.
- Replacing the live-gate verifier with evidence acquisition, or making a
  validation report the portable evidence payload. They may share bounded
  source/trigger primitives while retaining separate outcomes and owners.
- Broad SOC automation, arbitrary Cortex analyzer execution, new detector
  content, new Wazuh/Suricata rules, or general shell-session product redesign.
  Only the fixed contract readbacks/stimulus and the capture boundary required
  to observe already-authorized sessions are in scope.
- Migration of historical traces/run archives or indefinite retention in
  Tempo.
- Keeping obsolete TechVault observability nodes for backwards compatibility.
