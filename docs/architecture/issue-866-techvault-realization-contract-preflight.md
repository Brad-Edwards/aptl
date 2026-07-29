# Issue #866 TechVault Component Realization Preflight

This note fixes the repository-wide design boundaries for restoring honest
component behavior under dynamic RAES composition. It is architecture guidance,
not an implementation plan. [ADR-051](../adrs/adr-051-component-level-raes-realization.md)
is the binding source-selection decision.

The parity baseline is `docker-compose.yml` at commit
`304d1217f72d053b0e4201844eb731d5f513e24a`, the parent of the first
generic-materialization change. The baseline is evidence only. It must never be
read by the planner or deployment backend at runtime.

## Architecture Decisions

- Keep the authority chain unchanged:
  `techvault-operational.sdl.yaml` → RAES parse/compile/plan → typed APTL
  interpretation → `DeploymentBackend` → observed runtime snapshot.
- Reuse RAES artifact admission. `Source.artifact_requirement`,
  `ArtifactMechanismCapability`, `ArtifactAvailabilityContext`, planner
  artifact diagnostics, and `ArtifactSatisfactionDisclosureModel` are the
  source-selection and proof contracts. Do not add `source_type` to
  `AptlConfig`, an APTL source DTO, or a node-name lookup table.
- Select one source route per VM node. Eligible routes are exact pinned
  artifact pull, digest-bound per-component materialization, and dynamic
  generic composition. Switch nodes use the existing network realization
  concern.
- Require the complete runtime contract for every route. A vendor image
  supplies software; it does not waive declarations for effective
  configuration, identities, content, wiring, persistence, telemetry,
  integrations, or readiness.
- Make generic composition opt-in and closed. The route is inadmissible if any
  applicable runtime dimension is omitted, unsupported, not materialized, or
  not independently observable.
- Keep images component-scoped. A purpose-built image may contain one
  component's packages and invariant entrypoint. Scenario content, addresses,
  credentials, peer endpoints, certificates, accounts, and integration wiring
  remain runtime inputs.
- Preserve meaningful isolation boundaries. Wazuh log-forwarding sidecars and
  the Kali capture sidecar remain separate nodes because they enforce security
  ownership. One-shot initialization and host-publication proxies remain
  subordinate realization operations when they have no independent scenario
  identity.
- Generate or drive the effective local Docker model from the admitted typed
  realization. Checked-in Compose may retain APTL platform/control-plane
  services, but it is not the component catalog or the source of missing node
  behavior.
- Fail closed before mutation whenever source eligibility or contract
  completeness is known to be invalid. Failed semantic readiness after startup
  is a fatal unsuccessful apply, followed by existing scoped cleanup; it is not
  partial success.
- Keep `aptl lab start` on the local packaged Docker backend as the canonical
  target. Do not optimize this design around a direct developer script or a
  full-range CI boot.

## Source Selection Without A Duplicate Schema

The user-facing source labels in the matrices below are audit shorthand:

- **U:** exact pinned upstream/vendor artifact;
- **C:** purpose-built image for one component, produced by a digest-bound
  materialization specification; and
- **G:** generic runtime composition over a pinned base substrate.

They are not serialized values. The canonical identity is the selected RAES
artifact mechanism profile, acquisition/timing route, artifact identity, and
satisfaction disclosure.

Planning must intersect:

1. the node's authored permitted routes;
2. trusted availability facts for that compiled resource address;
3. the APTL manifest's supported artifact mechanisms and routes; and
4. the runtime concerns APTL can materialize and read back.

If more than one route remains, a deterministic, backend-owned preference
policy selects one. That policy is passed to a pure selector and keyed by
mechanism/profile, never by `techvault`, node name, Compose service, or local
cache contents. The selected route and artifact identity travel with the
existing typed node/image realization and are disclosed in the RAES snapshot.

### Current admission blockers

The installed RAES 2.0 contracts contain the required artifact mechanism,
availability, satisfaction, and rich `RuntimeConfiguration` models, but the
current realization-concern registry lowers only node type, OS family, content
type, domain topology, generated artifacts, persistent volumes, service-owned
content, and source artifacts. It does not yet emit realization requirements
for the runtime fields that make a component complete. Those concern
registrations, compiled payload paths, and non-approximation checks must exist
in RAES before APTL can claim complete component admission. An APTL-only
“complete” flag would duplicate the upstream contract and is forbidden.

APTL's current `create_aptl_manifest()` also publishes an empty
`artifact_mechanisms` tuple, no realization envelope, and no supported service
materialization profiles. `RuntimeManager.plan()` is currently called without
an `ArtifactAvailabilityContext`. These are honest descriptions of current
capability, not defaults to bypass. APTL may advertise a mechanism or readback
strength only after the corresponding selector, materializer, observer, and
snapshot satisfaction disclosure work end to end. Availability must enter the
existing RAES planning call as trusted, address-scoped facts; it must not be
constructed inside the planner from the local Docker cache.

## Network Contract

The four switch nodes are already present and retain the pre-refactor network
boundaries.

| RAES node | Baseline contract | Guardrail |
| --- | --- | --- |
| `security-net` | Bridge `172.20.0.0/24`, gateway `.1`, management/SOC connectivity, external routing allowed where host policy permits. | It is not a general participant-egress grant. Host publications for management services remain loopback-only. |
| `dmz-net` | Internal bridge `172.20.1.0/24`, gateway `.1`, public-facing target segment. | `internal: true` remains a range-escape control; intentional host exposure is separately declared. |
| `internal-net` | Internal bridge `172.20.2.0/24`, gateway `.1`, enterprise target segment. | No implicit host route or internet egress. |
| `redteam-net` | Internal bridge `172.20.4.0/24`, gateway `.1`, Kali operations segment. | Do not attach control-plane services or capture storage to the workload merely to simplify reachability. |

The Compose-only `aptl-control` bridge is a backend transport boundary for
loopback proxies. It is not a fifth scenario network and must not leak into the
RAES participant topology.

## Component Parity Matrix

The contract summaries cover operating system/software, services and
identities, content, topology/persistence, readiness, telemetry, and
integrations. “Gap” describes the present repository, not a permitted waiver.

| Pre-refactor component | RAES node or owner | Source | Required runtime contract and present gap |
| --- | --- | --- | --- |
| `wazuh.manager` | `wazuh-manager` | U | Wazuh manager/API, enrollment and syslog listeners; manager identity, rules/decoders/integrations, generated TLS and rendered config, retained `/var/ossec` state, three network attachments, loopback management publishes, indexer dependency, health plus authenticated API readiness, alert/log telemetry. Current `4.x` selector is not an immutable artifact requirement and the runtime contract is incomplete. |
| `wazuh.indexer` | `wazuh-indexer` | U | Wazuh indexer/OpenSearch API, JVM/resource limits, TLS and security config, retained index data, security network/static address, loopback API publish, health plus authenticated query readiness. Current `4.x` selector is not digest-pinned in RAES. |
| `wazuh.dashboard` | `wazuh-dashboard` | U | Dashboard service, indexer/manager credentials by reference, generated TLS and dashboard config, retained plugin/config state where required, loopback UI publish, dependencies, health and authenticated UI/API readiness. Current source-only node leaves effective runtime behavior in Compose. |
| `suricata` | `suricata` | U | Suricata 7 engine, IDS-only policy, config/rule seeds, command socket and MISP rule volumes, required bounded capabilities, three network attachments, process/rule-load readiness, EVE telemetry and Wazuh/MISP integrations. The image is pinned, but most effective contract remains outside the RAES node. |
| `misp` | `misp` | U | MISP application, HTTPS listener, DB/Redis dependencies, admin/key references, lab CA certificate, retained files/config, loopback UI, semantic login/API readiness, IOC telemetry. Source is pinned, but config, persistence, readiness, and integration declarations are incomplete. |
| `misp-db` | `misp-db` | U | MariaDB engine, database/user credential references, retained database, security network, initialization and query readiness, MISP-only integration. Digest source exists; runtime and persistence contract is missing. |
| `misp-redis` | `misp-redis` | U | Redis service, credential reference, memory bound, security network, command readiness, MISP integration, explicit persistence posture. Digest source exists; effective command/auth/readiness are not declared. |
| `misp-suricata-sync` | `misp-suricata-sync` | G | Python application and locked dependencies, service process, MISP URL/key/CA references, tag/filter/interval policy, shared rules/socket mounts, MISP/Suricata ordering, health/progress and structured logs. Current packages/content are a start but do not form a complete startup, environment, readiness, and telemetry contract. |
| `thehive` | `thehive` | U | TheHive service/API, Cassandra/Elasticsearch/Cortex bindings, keystore and secret references, application config, retained data/index, loopback UI, semantic API readiness and case telemetry. Source is pinned; runtime ownership is still Compose-heavy. |
| `thehive-cassandra` | `thehive-cassandra` | U | Cassandra cluster identity, heap limits, retained data, security network, CQL readiness and TheHive integration. Runtime and persistence declarations are absent. |
| `thehive-es` | `thehive-es` | U | Elasticsearch single-node service, security and disk-watermark posture, heap limits, retained data, cluster-health readiness, TheHive/Cortex integration. Runtime contract is absent. |
| `cortex-index-init` | `cortex` startup operation | U | One-shot index preparation using the admitted Elasticsearch artifact, contained script content, dependency on healthy `thehive-es`, completion readback, idempotency and bounded failure. It is not a steady-state node; making it a peer VM would confuse lifecycle with topology. |
| `cortex` | `cortex` | U | Cortex API/analyzer service, Elasticsearch/TheHive bindings, application config and generated TheHive key reference, retained analyzer/job data, loopback UI, index-init completion dependency, API readiness and analyzer telemetry. Source is pinned; the complete runtime contract is absent. |
| `shuffle-backend` | `shuffle-backend` | U | Shuffle API/backend, OpenSearch binding, secret references, retained app data, static address, readiness and workflow/execution telemetry. Source is pinned; environment, persistence, health, and integrations are incomplete in RAES. |
| `shuffle-frontend` | `shuffle-frontend` | U | HTTP/HTTPS UI, backend binding, TLS/runtime config, loopback publishes, backend dependency, UI readiness. Source is pinned; effective runtime contract is absent. |
| `shuffle-orborus` | `shuffle-orborus` | U | Orborus worker/orchestrator, backend binding, least Docker authority required by the product, static address, job-loop readiness and execution telemetry. Source is pinned; privileged/runtime integration must be explicit and security-reviewed. |
| `shuffle-opensearch` | `shuffle-opensearch` | U | OpenSearch single-node service, security posture, JVM/resource limits, retained data, cluster readiness, Shuffle-only integration. Source is pinned; runtime/persistence contract is absent. |
| `webapp` | `webapp` | G | Linux, Flask/Gunicorn/PostgreSQL client and rsyslog packages, application/config/service content, service identity, DB dependency, DMZ/internal addresses, intentional target exposure, CTF content, access-log forwarding, process/listener and database-semantic readiness. Current declaration is close but must explicitly cover persistence posture, identities, environment references, integrations, and semantic probes. |
| `mailserver` | *(none: out of scope)* | n/a | `aptl.json` sets `mail: false`, so this service is not selected by the configured public profile set. ADR-046's non-goals forbid promoting an inactive legacy profile into scenario scope. Restoring it is a separate scenario-authoring decision, not part of this cutover. |
| `dns` | `dns` | G | Bind9/dnsutils, named service, TechVault zones/config, service identity and log ownership, three networks/static addresses, intentional TCP/UDP 5353 host publication, query/zone readiness, DNS telemetry and enterprise integration. Current declaration needs explicit persistence, environment, semantic readiness, and logging contract. |
| `ad` | `ad` | C | One Samba AD component image, domain bootstrap mechanics, Kerberos/LDAP/SMB/DNS services, domain/controller identities and accounts, retained directory/log state, internal static address, bounded capabilities, Wazuh telemetry, domain and protocol readiness. The present node has no source or runtime and is inadmissible. Scenario domain, users, SPNs, passwords, and topology stay outside the image. |
| `db` | `db` | G | Linux PostgreSQL package/service, database identity and credential references, schema/seed/bootstrap content, retained data, internal static address, SQL readiness, webapp/fileshare integrations and database telemetry. Current contract needs explicit storage, identity, environment, integration, and semantic-query readback. |
| `fileshare` | `fileshare` | G | Samba package/service, config and share content, local/domain identity bindings, retained share/log data, internal static address, bounded capability, SMB readiness, planted scenario content and Wazuh telemetry. Current declaration does not yet state all identities, persistence, telemetry, and semantic share probes. |
| `wazuh-sidecar-db` | `wazuh-sidecar-db` | C | Dedicated Wazuh forwarding-agent image, unique agent identity, read-only DB log mount, manager endpoint/credential references, security static address, manager ordering, enrollment/forwarding readiness. No source/runtime is declared today. It remains separate from `db` to preserve mount and agent ownership. |
| `wazuh-sidecar-suricata` | `wazuh-sidecar-suricata` | C | Dedicated Wazuh forwarding-agent image, unique agent identity, read-only EVE mount, manager endpoint/credential references, security static address, manager ordering, enrollment/forwarding readiness. No source/runtime is declared today. |
| `victim` | `victim` | C | One target-host image with the approved OS/toolchain and invariant boot mechanics; SSH, sudo, Wazuh/Falco or explicitly equivalent telemetry, lab identities and authorized keys, CTF content, retained logs, internal static address, service and telemetry readiness. Current generic declaration restores only a subset and is hollow against the baseline. |
| `workstation` | `workstation` | C | One workstation image with the approved OS/client toolchain and invariant boot mechanics; SSH, identities/sudo, pivot and database-client content, CTF/loot ownership, retained logs, internal static address, Wazuh/Falco or explicitly equivalent telemetry, SSH and attack-path readiness. Current generic package subset is not parity. |
| `kali` | `kali` | C | One Kali component image with pinned repositories/toolset and invariant SSH/capture bootstrap; Kali identity, authorized/pivot keys, operations state, red/DMZ/internal addresses, bounded attack capabilities, usable SSH/tool readiness. Current Debian generic package subset explicitly omits Kali metapackages and is not admissible parity. Capture evidence remains outside this image. |
| `kali-ssh-proxy` | `kali` host-publication operation | C | Loopback-only host bridge to the admitted Kali SSH listener, isolated `aptl-control` attachment, fixed target binding derived from the node attachment, bounded resources and connect readiness. It is backend transport, not a participant/scenario node. Its component build must not hardcode TechVault topology. |
| `kali-capture` | `kali-capture` | C | Dedicated capture image, shared Kali network namespace but separate PID/mount namespaces, sole capture-volume ownership, audit/tcpdump/accounting services, exact capability set, no host ports, bootstrap/readiness and harvest telemetry. No source/runtime is declared today; collapsing it into Kali is forbidden by ADR-041/042. |
| `reverse` | *(none: out of scope)* | n/a | `aptl.json` sets `reverse: false`, so this service is not selected by the configured public profile set. ADR-046's non-goals forbid promoting an inactive legacy profile into scenario scope. Restoring it is a separate scenario-authoring decision, not part of this cutover. |
| `aptl-web-api` | APTL platform control plane | C | FastAPI BFF, Docker control boundary, strict token/session/CSRF handling, loopback API, project read-only mount and readiness. It is documented from the baseline but is not a TechVault RAES node: a scenario must not instantiate the control plane that admits that scenario. ADR-039 remains authoritative. |
| `aptl-web-ui` | APTL platform control plane | C | Static UI/Caddy same-origin proxy, API dependency, loopback UI and HTTP readiness. It remains outside the TechVault graph and receives no control-plane token. |
| `aptl-otel-collector` | `aptl-otel-collector` | U | Collector service, checked-in config, OTLP listeners, loopback publishes, security network, config/health readiness, trace routing and bounded resources. Source is pinned; runtime configuration and telemetry contract need full declaration. |
| `aptl-tempo` | `aptl-tempo` | U | Tempo service, checked-in config, retained trace data, loopback query/API, security network, ingest/query readiness and collector/Grafana bindings. Source is pinned; runtime/persistence/readiness are incomplete. |
| `aptl-grafana-otel` | `aptl-grafana-otel` | U | Grafana service, admin credential references, datasource config, retained state, loopback UI, Tempo dependency, authenticated readiness. Source is pinned; effective runtime contract is incomplete. |

`mailserver` and `reverse` are **out of scope**, not migration gaps. `aptl.json`
sets `mail: false` and `reverse: false`, so neither is selected by the configured
public profile set, and ADR-046's non-goals state that a service is not promoted
into TechVault scope "merely because it existed in that file." Restoring either is
a separate scenario-authoring decision, not part of this parity cutover.
`cortex-index-init` and `kali-ssh-proxy` map to their owning node contracts
because they are lifecycle/transport helpers, not independent scenario
systems. The APTL web services remain outside the scenario authority boundary.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| SDL shape and runtime vocabulary | RAES `Source`, `ArtifactRequirement`, `RuntimeConfiguration`, typed service-family models, stateful resources, content/accounts, conditions, `RealizationDesignation`, parser, compiler, and `CompiledRealizationRequirement`. Extend registered realization concerns when a runtime field is not yet gated; do not mirror the models in APTL. |
| Artifact admission and proof | RAES `ArtifactMechanismCapability`, `ArtifactAvailabilityContext`, `artifact_requirement_diagnostics()`, `evaluate_artifact_realization()`, and `ArtifactSatisfactionDisclosureModel`. |
| Backend capability honesty | `create_aptl_manifest()`, `ProvisionerCapabilities`, `RealizationSupportDeclaration`, the realization envelope, and RAES conformance. Mechanisms are declared only after end-to-end materialization and readback exist. |
| APTL interpretation | `interpret_provisioning_plan()`, `NodeRealization`, `AptlRealization`, `DeploymentImageRealization`, `DeploymentNodeRealization`, and `DeploymentRealizationSpec`. Extend these existing carriers; do not add a second plan. |
| Image trust and build mechanics | `raes_image_realization.py`, contained project build paths, digest validation, generated image overrides, and `_prepare_realization_images()`. Replace the local product allowlist as authority with admitted RAES artifact facts; retain its path and image-reference safety checks as backend defense in depth. |
| Generic composition | `raes_base_substrate.py`, `raes_materializer.py`, `raes_materializer_engine.py`, `raes_docker_materializer.py`, and `raes_node_materialization.py`. Add typed operations/readback where the canonical runtime schema grows; never branch on a product name. |
| Content and identities | Existing content/account placement resolvers, `_resolve_within_project()`, `forbidden_source_reason()`, domain-controller/account providers, and read-after-write checks. |
| Generated config, TLS, and persistence | ADR-028/034/043, `ComposeStatefulRealizationMixin`, stateful validators, certificate/config producers, `DeploymentGeneratedArtifactRealization`, and `DeploymentPersistentVolumeRealization`. Images do not absorb these owners. |
| Network and host exposure | `DeploymentNetworkRealization`, `DeploymentNetworkAttachment`, `DeploymentPublishedPort`, ACL realization, network labels/readback, `LOOPBACK_HOST_IP`, and the endpoint registry. |
| Deployment execution | `DeploymentBackend`, `DockerComposeBackend`, `SSHComposeBackend`, typed runner methods, project-name scoping, timeouts, generated Compose validation, service health waits, and cleanup. No raw Docker subprocesses in RAES adapters or validators. |
| Lifecycle and errors | `ApplyResult`, RAES `Diagnostic`, `render_raes_diagnostics()`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, API `LabActionResponse`, and existing CLI rendering. |
| Logging and persistence | `get_logger()`, `redact()`, `LocalRunStore` redacting JSON/JSONL writes, `RangeSnapshot.to_dict()`, RAES runtime snapshot/provenance, and operation status/history. |
| Gates and regression patterns | `techvault_gate.py`, the current image-free declaration gate as the replacement point, live/curated gates, realization lowering tests, mixed-dispatch tests, deployment backend tests, static conformance tests, and clean-start integration wiring. |

## Security And Validation Passage

| Layer | Required behavior |
| --- | --- |
| RAES parser and schema | `Source.artifact_requirement`, runtime fields, stateful resources, content, identities, network declarations, and readiness references pass the existing strict Pydantic and semantic validators. Authored empty versus omitted contract dimensions must survive compilation so omission cannot masquerade as satisfaction. |
| Realization designation and compiler | Closed TechVault fields produce typed realization requirements with compiled addresses and provenance. Open realization is allowed only where explicitly authored and where APTL declares open support. A missing concern is not silently backend-owned. |
| Artifact planner admission | Availability facts are address-scoped and trusted. Exact digests, locked inputs, materialization specifications, permitted routes, trust references, and manifest mechanism support all pass RAES artifact diagnostics before APTL mutation. Do not infer availability from `docker image ls` alone or accept a mutable tag. |
| APTL interpretation/admission | Every VM gets exactly one selected route and a complete typed contract. Replace the current “`runtime` exists or image resolved” predicate; it currently accepts a small package subset and cannot distinguish a configured vendor image from a generic node. Diagnostics use stable codes and compiled addresses. |
| Config shape | Durable non-secret backend policy belongs in strict `AptlConfig` only if operators genuinely need to vary it. Source selection, component mappings, and trust rules are not unchecked `aptl.json` dictionaries. Existing `ContainerSettings`, `DeploymentConfig`, and project-name validation remain authoritative. |
| Environment and secret binding | Continue through `hydrate_dotenv()`, `load_dotenv()`, `EnvVars`, `env_vars_from_dict()`, required-variable checks, and `find_placeholder_env_values()`. SDL/runtime contracts carry variable references and sensitivity, never values. Vendor and component image builds receive no runtime secrets. Service-specific environment parsers remain authoritative where `EnvVars` does not own that service; do not broaden `EnvVars` into a generic secret bag. |
| Content/path policy | Project content passes forbidden-source policy, project containment, symlink/path checks, and typed content realization. `.env`, Git data, private TLS material, and unlisted keys cannot become node content. Generated secrets remain producer-owned artifacts, not scenario files or image layers. |
| Supply chain and build context | Upstream images are immutable digest identities. Component builds use digest-bound materialization specifications, verified locked inputs, contained contexts, associated manifests, and provenance. Never execute raw `Source.build` history, untrusted Dockerfile text, or scenario-provided shell. |
| Capability and container policy | Reuse the Linux capability allowlist, init requirements, mount-kind validation, resource bounds, seccomp/cgroup decisions, and ADR-041/042 namespace boundaries. A purpose-built image does not authorize new host capabilities. |
| Network/auth surface | Reuse ACL admission, internal-network isolation, loopback management defaults, endpoint registry, lab CA, web authentication, SSH host-key verification, and Kali proxy/capture separation. Source choice must not widen exposure. |
| OS/process exposure | Backend commands remain argv lists under existing typed runner methods. Credentials, cookies, tokens, private-key bytes, rendered config, prompts, and secret-bearing URLs never enter argv, image labels/history, logs, or diagnostics. Container probes use bounded timeouts and the existing `curl_safe`/typed service helpers; do not add raw credential-bearing `curl`, registry, or shell invocations. |
| Effective Compose model | Render and validate the generated model before startup, without secret interpolation where stateful validation requires it. Reject duplicate containers, ports, mounts, networks, or helper ownership. Checked-in scale-zero stubs are not proof of a node contract. |
| Readiness and semantic proof | Reuse service health waiting, provisioner completion markers, authenticated Wazuh checks, backend inspect/exec, and existing live-gate collectors. “Container running” and “port open” are insufficient for products whose baseline contract requires login, query, enrollment, data flow, or integration proof. |
| Error envelope | Planner failures remain RAES diagnostics; backend failures become unsuccessful `ApplyResult`/`LabResult`; CLI/API use existing envelopes. Raw registry, Docker, subprocess, HTTP, or parser output is not copied into user-visible errors. Contract failure is fatal, not `DEGRADED_USABLE`. |
| Logging and persistence | All diagnostic/log messages pass `redact()` or an existing redacting boundary. Persist artifact identity, selected mechanism, digests, proof refs, readiness outcomes, and snapshot state through `LocalRunStore`/RAES contracts. Do not persist env values, raw build args, rendered secrets, or private keys. |
| Participant projection | Infrastructure restoration must not add participant-visible nodes, credentials, evaluator-only evidence, actions, observations, or workbench links. Existing observation boundaries and participant profile qualification remain the disclosure authority. |

## Extensibility Seam

The seam is:

`(compiled resource address, ArtifactRequirement, ArtifactAvailabilityContext,
manifest artifact mechanisms, deterministic route preference,
RuntimeConfiguration concerns, DeploymentBackend)`

The selector returns one existing RAES mechanism/artifact identity plus the
typed backend realization data. The next reasonable variation (a signed remote
component image, a different digest-bound build profile, or another honest
generic base) changes availability, mechanism capability, or route preference.
It must not require a TechVault branch, a new source enum, or edits to every
component mapping.

Runtime-contract support is independently extensible by RAES concern kind and
typed materializer/readback handler. Adding one runtime capability extends the
canonical concern registry, APTL manifest, typed operation, and observer; it
does not add a product-specific provisioner.

## Whole-Repository Surface In Scope

- RAES dependency contracts: `Source.artifact_requirement`,
  `RuntimeConfiguration`, realization designation/requirements, artifact
  admission, availability, satisfaction disclosure, planner, manifest, and
  conformance.
- Scenario authority:
  `scenarios/techvault-operational.sdl.yaml`, `scenarios/catalog.json`,
  generated artifacts, persistent volumes, accounts, content, conditions, and
  participant projection.
- APTL adapter:
  `src/aptl/backends/raes_{manifest,realization,realization_model,image_realization}.py`,
  placement/content/account/stateful resolvers, diagnostics, observation, and
  reproducibility records.
- Generic materializer:
  `src/aptl/backends/raes_{base_substrate,materializer,materializer_engine,docker_materializer,node_materialization}.py`.
- Deployment:
  `src/aptl/core/deployment/realization.py`,
  `backend.py`, Compose image/network/content/account/stateful/health/port/base
  realization modules, local and SSH Compose backends, runner, cleanup, and
  snapshot inventory.
- Cross-cutting host/runtime policy:
  `src/aptl/core/{config,env,lab,lab_types,runstore,snapshot,soc_ca,ssh}.py`,
  credential/rendered-config producers, endpoint registry, redaction/logging,
  capability/content-source policy, and continuity checks.
- Packaged assets: individual component Dockerfiles/build contexts, service
  config under `config/`, seed content under `scenarios/fixtures/`, generated
  `.aptl/realization` artifacts, and `docker-compose.yml` only for the retained
  platform/backend base.
- Gates/tests: TechVault static/live/curated validation, RAES conformance,
  realization lowering, artifact admission/satisfaction, generic materializer,
  mixed source dispatch, generated Compose validation, readiness, secret
  leakage, snapshot/run-store, network exposure, and clean packaged startup.
- Workflow: `.ground-control.yaml`, `.gc/plan-rules.md`,
  `.pre-commit-config.yaml`, `.github/workflows/checks.yml`, `pytest`,
  `pre-commit run --all-files`, and the documented clean
  `aptl lab stop -v && aptl lab start` requirement for deployment/config
  changes.

## Gotchas And Anti-Patterns

- Do not treat `source.version: 4.x`, `latest`, a tag-to-digest resolver, or an
  image already present locally as an immutable authored artifact.
- Do not expand `_ALLOWED_SOURCE_IMAGE_REFS` into the new component catalog.
  RAES artifact requirements and availability are the authority; local syntax
  and path checks remain defense in depth.
- Do not dispatch generic composition merely because `runtime` is non-null.
  Vendor images also need runtime configuration, so that test conflates source
  choice with effective state.
- Do not declare artifact mechanisms, service-materialization profiles, or
  realization-envelope observation strength ahead of the corresponding
  backend execution and independent readback. Manifest overclaim turns planner
  admission into a false assurance.
- Do not treat today's limited RAES realization-concern registry as proof that
  unregistered runtime fields are open or backend-owned. Extend the upstream
  registry and snapshot paths; do not compensate with an APTL completeness
  boolean.
- Do not retain the global `image_free` boolean as the route authority. Source
  selection is per node; a mixed graph is normal.
- Do not accept package presence, process existence, container health, or an
  exposed port as proof of the complete component contract.
- Do not let `docker-compose.yml`, profile aliases, service names, scale-zero
  stubs, or `depends_on` fill declarations missing from the RAES graph.
- Do not create APTL-local mirrors of `ArtifactRequirement`,
  `RuntimeConfiguration`, artifact satisfaction, diagnostics, availability, or
  readiness.
- Do not turn the parity matrix into a runtime manifest. It is review evidence;
  the operational contract is encoded once in RAES.
- Do not use one purpose-built image for multiple meaningful TechVault
  components or bake peer addresses, credentials, certificates, accounts,
  seeded participant content, or integration endpoints into a component image.
- Do not collapse Wazuh sidecars into workloads or Kali capture into Kali.
  Their separate namespaces and mount ownership are security controls.
- Do not promote `cortex-index-init` or host proxies into participant-visible
  topology merely because Compose represented them as containers.
- Do not model the APTL web control plane as a scenario node. That creates a
  recursive authority and risks exposing the Docker socket/token boundary.
- Do not add raw `docker`, Compose, registry, SSH, or `curl` calls outside the
  incumbent deployment, build, or safe HTTP boundaries.
- Do not pass secrets as Docker build args, image environment defaults, labels,
  commands, health-check text, process argv, or diagnostic details.
- Do not continue startup after an incomplete or unverifiable required node.
  Cleanup success does not convert failed admission/realization into a degraded
  lab.
- Do not change participant actions, observations, task text, bookmarks, or
  evaluator visibility while restoring infrastructure parity.

## Non-Goals And Boundaries

This issue does not implement Kubernetes, cloud fleets, nested virtualization,
or a mandatory appliance boundary. It does not create a reduced or
event-specific TechVault, require full-range CI, redesign participant agency,
replace the endpoint registry, change web/terminal authentication, or make the
old Compose file authoritative again.

The implementation boundary is component admission, realization, runtime
wiring, semantic readiness, and evidence on the local packaged Docker path.
Platform control-plane containers and subordinate backend helpers remain
outside participant topology. Restoring missing infrastructure must preserve
the participant-visible `techvault-operational` contract.
