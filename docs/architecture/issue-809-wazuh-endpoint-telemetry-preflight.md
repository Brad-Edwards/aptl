# Issue #809 Wazuh Endpoint Telemetry Preflight

This note fixes the repository-wide design boundaries for restoring Wazuh
endpoint telemetry to dynamically realized TechVault nodes. It is architecture
guidance, not an implementation plan. The binding decisions are
[ADR-020](../adrs/adr-020-wazuh-agents-in-process-vs-sidecar.md) for agent
placement and [ADR-051](../adrs/adr-051-component-level-raes-realization.md)
for component source selection. The realization authority chain remains the
one in [ADR-046](../adrs/adr-046-dynamic-raes-scenario-realization.md).

The parity baseline is `docker-compose.yml` at commit
`304d1217f72d053b0e4201844eb731d5f513e24a`. It is evidence only and must not
become runtime input. The configured public TechVault scenario is supplied by
the exactly pinned `raes-env-packs` package; its installed copy is not an
authoring location. Pack changes belong in the package source and enter APTL
through the existing validated bundle and pinned dependency path.

## Baseline Enrollment Contract

The baseline has eight Wazuh identities. Six represent agents running in the
attacked node's process and filesystem namespaces. Two are the narrow sidecar
exceptions already allowed by ADR-020.

| Logical node | Baseline placement | Existing identity behavior | Required boundary |
| --- | --- | --- | --- |
| `webapp` | In process | `aptl-webapp-agent` | Host/application logs and endpoint state come from the web node, not a generic syslog substitute. |
| `ad` | In process | `aptl-ad-agent` | Samba/AD and host evidence retain the AD node identity. |
| `dns` | In process | `aptl-dns-agent` | Named/DNS and host evidence retain the DNS node identity. |
| `fileshare` | In process | `aptl-fileshare-agent` | Samba/fileshare and host evidence retain the fileshare node identity. |
| `victim` | In process | Timestamped name at every boot | Replace the collision-prone timestamp behavior with one deterministic logical identity. |
| `workstation` | In process | Timestamped name at every boot | Replace the collision-prone timestamp behavior with one deterministic logical identity. |
| `wazuh-sidecar-db` | Sidecar | `aptl-db-agent` | Preserve the read-only PostgreSQL log-forwarder ownership boundary. |
| `wazuh-sidecar-suricata` | Sidecar | `aptl-suricata-agent` | Preserve the read-only EVE forwarder, while treating its output only as network evidence. |

The two sidecars remain enrolled agents but do not prove host-correlated
endpoint telemetry. A representative acceptance probe must target one of the
six in-process endpoints and must identify that endpoint in the resulting
Wazuh alert.

`mailserver` and `reverse` are not selected by `aptl.json`; their legacy agents
are outside this issue. Kali deliberately remains outside Wazuh endpoint-agent
scope under
[ADR-033](../adrs/adr-033-agent-reasoning-trace-boundary.md). Existing manager,
indexer, and infrastructure health are dependencies, not additional endpoint
identities.

## Architecture Decisions And Guardrails

- The RAES runtime graph is the desired-state authority. Each required node
  declares its canonical `forwarding_agents` contract and the manager declares
  the corresponding enrolled-agent references. Environment variables,
  comments, checked-in Compose services, and an agent binary present in an
  image are not substitutes for that typed contract.
- Enrollment is a semantic relationship among a logical node, one agent
  identity, and the manager selected through the existing service-family and
  dependency model. Do not infer it from the literal hostname
  `wazuh-manager`; the current pack contains stale `wazuh.manager` values, and
  `_wazuh_identity.py` already provides semantic manager discovery.
- The source selected under ADR-051/#866 and integrated by #869 supplies the
  component. Purpose-built nodes reuse `containers/_wazuh-agent/` for package,
  rendered configuration, registration, and process supervision. Generic
  materialization may be used only when the existing typed package/content/
  identity/service operations express the complete contract and readback.
  Wazuh-specific switches do not belong in the product-neutral materializer.
- Agent names are deterministic functions of the compiled logical node
  address. They must be unique within one manager and stable across documented
  restart/recreate behavior. Independent disposable seats already isolate the
  whole manager state; if a future topology shares a manager, the existing
  deployment/seat namespace is the additional input rather than a timestamp or
  random suffix.
- Endpoint `client.keys` state and manager enrollment state form one lifecycle
  contract. A preserved lifecycle retains compatible state on both sides; a
  recreate may idempotently re-enroll the same logical identity and reconcile
  the old record; a clean/project-volume reset removes both. Manager `<force>`
  is a reconnect mechanism, not the sole persistence model and never a reason
  to accumulate stale identities.
- Readiness is derived from the declared agent graph, not from a second list of
  TechVault node names. For every required identity it verifies one manager
  record, `Active` connection state, a bounded recent keepalive, and agreement
  with the expected logical node. It also verifies the node-local contract:
  installed package, rendered manager/name configuration, non-empty enrollment
  state, supervised daemon, and configured log sources that exist and are
  readable. Sidecars additionally retain their declared read-only source
  mounts.
- Missing, duplicate, never-enrolled, or disconnected required agents are
  fatal post-start semantic-readiness failures. They flow through the existing
  unsuccessful `ApplyResult`/`LabResult` and scoped cleanup path. They are not
  ADR-030 `DEGRADED_USABLE` warnings. Container health, manager API health, and
  RAES forwarding-agent mount observation are necessary corroboration but do
  not satisfy endpoint readiness.
- The bounded alert proof extends the existing TechVault live-gate probe and
  Wazuh collector. A unique action marker is generated after collection
  begins; a passing alert has a rule, a post-trigger timestamp, that marker,
  and the exact expected `agent.name` for the target endpoint. Persist only a
  bounded correlation summary/digest. Suricata results remain a separate
  supporting channel and cannot make the endpoint check pass.
- Wazuh manager policy remains centralized in
  `config/wazuh_cluster/wazuh_manager.conf` and its existing custom rules,
  decoders, active-response scripts, and integration directories. Extend those
  owners only when the representative action is not already decoded. Do not
  copy rule/decoder files into endpoint images or create per-node manager
  policy trees.
- Active-response privilege and telemetry are separate contracts. Do not grant
  `NET_ADMIN`, writable host paths, or another capability to `victim` or
  `workstation` merely to make their agents observable. Existing capability
  admission and ADR-020 remain authoritative where active response is actually
  required.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Scenario and forwarding schema | RAES `RuntimeConfiguration`, `RuntimeForwardingAgent`, security-monitoring manager/agent models, `ship_targets`, service references, persistent volumes, parser, compiler, semantic validators, and realization-concern registry. Do not create APTL Wazuh DTOs or a parallel enrollment schema. |
| Pack identity and validation | `raes_env_packs.validate_pack()`, content-manifest validation, `scenario_bundle.py`, the pinned `raes-env-packs` dependency, and `tests/helpers.py::techvault_scenario_path`. Never edit or test against an installed `.venv` copy directly. |
| Component agent mechanics | `containers/_wazuh-agent/install.sh`, `ossec.conf.template`, `wazuh-agent.sh`, and `aptl-firewall-drop.sh`; `containers/wazuh-sidecar/Dockerfile` is the shared sidecar source. Fix common lifecycle behavior once, not in node-specific forks. |
| Component realization | ADR-051 artifact admission plus `raes_image_realization.py` for component images, or `raes_materializer.py`, `raes_materializer_engine.py`, `raes_docker_materializer.py`, and `raes_node_materialization.py` for genuinely complete generic composition. |
| Manager selection and wiring | `src/aptl/core/deployment/_wazuh_identity.py`, declared RAES dependencies/service families, and generated Compose lowering in `_compose_node_generation.py`. Do not branch on scenario names or handwritten Compose container names. |
| Manager policy | `config/wazuh_cluster/wazuh_manager.conf`, `sync_manager_config`, and the existing files under `config/wazuh_cluster/` for AD, web, Samba, PostgreSQL, Suricata, Falco, Shuffle, and active response. |
| Generated config and secrets | ADR-025/028/029, `AptlConfig`, `hydrate_dotenv()`, `load_dotenv()`, `EnvVars`, `env_vars_from_dict()`, placeholder rejection, `.aptl` containment, atomic writes, and restrictive file modes. |
| Persistence and lifecycle | RAES persistent-volume declarations, `ComposeStatefulRealizationMixin`, stateful graph validation, project-scoped volumes, `_compose_stop.py`, ADR-043/045, and disposable-seat isolation in `appliance/seat/lifecycle.py`. |
| Backend execution | `DeploymentBackend`, `DockerComposeBackend`/`SSHComposeBackend`, typed argv runners, project-label scoping, `BackendTimeoutError`, generated-Compose validation, and existing inspect/exec methods from ADR-037. |
| Semantic readiness | `_compose_post_start.py`, `_compose_stateful_readiness.py`, `wait_for_service()`, `check_manager_api_ready()`, bounded backend inspection, and the existing startup outcome/error envelopes. Manager API readiness must be extended/reused, not replaced by a second Wazuh client path. |
| Alert evidence | `collect_wazuh_alerts()`, `_live_gate_probes.py`, `_live_gate_telemetry.py`, `LiveGateReport`, `LiveGateCheck`, and the redacted live-gate manifest. Extend correlation semantics in this path rather than adding an issue-specific harness. |
| Observation and evidence | RAES runtime observation, `RangeSnapshot`, `LocalRunStore`, `get_logger()`, and `redact()`. Forwarding-agent observation currently proves host-visible footprint only and must not be relabeled as enrollment proof. |
| Regression contracts | `test_techvault_telemetry_spine.py`, `test_in_process_agents.py`, `test_wazuh_active_response.py`, env-pack realization tests, live-gate tests, lifecycle tests, and the packaged clean-host proof owned by #870. One graph-derived expected set replaces duplicate hard-coded subsets. |

## Security And Validation Passage

| Layer | Required behavior |
| --- | --- |
| Pack and schema validation | The package passes pack/digest/content validation before RAES parsing. Forwarder IDs are unique; manager/node/service references resolve; source profiles and log-source shapes pass the existing Pydantic and semantic validators. A static TechVault parity assertion checks that the manager declaration and required forwarder graph are a bijection; it does not introduce another schema. |
| RAES admission and realization | The selected #866 source route, runtime concern requirements, capability declaration, exact/non-approximation gate, materialization operation, and independent readback all succeed. A forwarding mount without install/service/enrollment support remains incomplete. |
| APTL config and environment shape | No new operator setting is needed for fixed TechVault agent membership. Non-secret manager target, stable agent identity, log paths, and service settings lower from typed RAES fields. Any operator value continues through strict `AptlConfig`/`EnvVars` parsing and placeholder rejection; arbitrary environment dictionaries do not become a second configuration API. |
| Enrollment secret surface | Current lab authd enrollment is passwordless, so do not invent or serialize a credential. If password enrollment is later enabled, the value is a generated/operator-secret reference rendered with restrictive permissions and is excluded from SDL literals, image layers, argv, logs, diagnostics, snapshots, and manifests. `client.keys` is always secret state. |
| Generated files and paths | Rendered `ossec.conf`, keys, and any enrollment helper files stay in project-scoped generated/persistent locations, pass containment and mount-conflict checks, and use restrictive modes. Do not mutate checked-in config or place credentials in a shared world-readable mount. |
| Container and network policy | Wazuh 1514/1515 traffic remains on declared range networks; management API publications retain loopback defaults. Sidecar log mounts remain read-only. Existing capability, mount-kind, resource, seccomp, and network validators apply; source choice cannot widen ports or privilege. |
| OS/process exposure | Commands use typed backend argv lists and bounded timeouts. Wazuh API credentials use `curl_safe`/existing authenticated helpers, never `curl -u` or shell interpolation visible in process argv. Agent bootstrap must not tee enrollment keys or unbounded raw `agent-auth` output into container logs. |
| Semantic readiness | The authenticated manager query is bounded and paginated/filtered to the declared set, normalizes Wazuh's response envelope through one client seam, and treats malformed, ambiguous, stale, duplicate, or missing records as failure. Node-local probes return structured statuses, not secret-bearing command output. |
| Error envelope | Parser/planner failures remain RAES diagnostics; realization/readiness failures use existing `ApplyResult`, `LabResult`, `StartupOutcome`, and `StartupDiagnostic` shapes; live proof uses existing gate checks. Raw HTTP bodies, subprocess output, manager credentials, agent keys, and rendered config never enter user-visible errors. Do not add a Wazuh exception hierarchy. |
| Logging and retained evidence | Log compiled node address, logical agent name, phase, bounded status, count, and stable diagnostic code. Apply `redact()` at persistence boundaries. Retain timestamps, rule ID, endpoint identity, action-marker digest, and evidence digest where needed; never retain credentials, `client.keys`, raw auth output, or an unbounded alert corpus. |

## Extensibility Seam

The seam is the existing typed relation:

`(compiled node address, placement mode, logical agent identity, log-source
set, manager target reference, lifecycle scope)`.

The manager's expected set and semantic readiness are derived from that
relation. Adding the next endpoint or choosing the existing sidecar carve-out
changes the scenario/component declaration and source realization, not a
Python node-name table, a second readiness DTO, or the live-gate workflow.
Log-source paths and formats and the manager target are parameters; placement
mode remains the ADR-020 choice. A deployment/seat namespace is an optional
identity input only if a later architecture shares one manager across ranges.

The manager API helper is the other intentional seam: it should return a
normalized, bounded agent-status view usable by startup readiness, live proof,
and tests. Authentication, transport safety, pagination, response validation,
and redaction stay inside that one incumbent service boundary.

## Whole-Repository Surface In Scope

- The package-owned TechVault SDL, its content manifest/digests, APTL's pinned
  `raes-env-packs` dependency, bundle staging, and pack validation.
- ADR-051 source admission, component Dockerfiles and shared Wazuh assets, and
  the generic materializer/readback only for nodes that honestly use that
  route.
- RAES forwarding-agent, manager-agent, service-reference, runtime environment,
  mount, persistent-volume, capability, and published-port concerns.
- APTL interpretation, generated Compose lowering/validation, semantic Wazuh
  manager discovery, stateful realization, post-start readiness, cleanup, and
  snapshot observation.
- Manager config, custom rules/decoders/integrations, agent enrollment port,
  endpoint process/filesystem state, read-only sidecar mounts, and project- or
  seat-scoped lifecycle state.
- Static TechVault conformance, telemetry-spine and in-process-agent tests,
  lifecycle/reconnect tests, the existing bounded live gate, and #870's
  packaged clean-host invocation of that same public validation path.

## Gotchas And Anti-Patterns

- Do not equate rsyslog delivery with a Wazuh endpoint agent, or Suricata noise
  with host-correlated evidence.
- Do not use container existence, manager health, an open port, an image layer,
  or a mounted log path as enrollment/connection proof.
- Do not restore only `docker-compose.yml`; generated env-pack realization is
  the configured authority. Do not edit the package installed under `.venv`.
- Do not use timestamps, container IDs, ephemeral IPs, or random suffixes for
  identities. Do not maintain separate expected-agent lists in scenario,
  readiness, live gate, and tests.
- Do not hard-code `wazuh.manager` or `wazuh-manager`; resolve the declared
  manager. In particular, do not preserve the stale dotted manager value now
  present on several pack nodes.
- Do not fork the shared agent bootstrap, duplicate Wazuh rules/decoders, add a
  Wazuh product branch to the generic materializer, or add parallel config,
  readiness, error, or evidence schemas.
- Do not rely on the manager force window as identity persistence, fixed sleeps
  as readiness, or an unbounded alert search as correlation.
- Do not expose Wazuh credentials in process arguments or diagnostics, log
  enrollment key material, persist raw alerts unnecessarily, widen management
  publications, or add capabilities solely for telemetry.
- Do not let the sidecar Suricata agent satisfy the representative endpoint
  proof, and do not let a unique username match pass without the expected
  endpoint `agent.name`, rule, and event time.

## Non-Goals And Implementation Boundaries

- No universal RAES package-repository abstraction is required. Component
  images, pinned upstream artifacts plus runtime config, and complete generic
  composition remain the source choices defined by ADR-051.
- This issue does not redesign Wazuh manager/indexer/dashboard, the live-gate
  report schema, startup outcome types, deployment backends, or disposable-seat
  isolation.
- It does not add Kubernetes/cloud support, a shared multi-range Wazuh manager,
  or agents for disabled `mailserver`/`reverse` nodes or Kali.
- It does not make every endpoint an active-response target or weaken container
  isolation to do so.
- It does not treat infrastructure health, network IDS evidence, or generic
  syslog forwarding as an acceptable substitute for enrolled, connected,
  node-correlated endpoint telemetry.
