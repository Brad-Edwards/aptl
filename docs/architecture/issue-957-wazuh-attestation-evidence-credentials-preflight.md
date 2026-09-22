# Issue 957: Wazuh Attestation, Evidence, and Credentials Preflight

**Status:** Accepted implementation guidance

**Scope:** Architecture guardrails for issue 957; this note is not an
implementation plan.

## Decision Summary

APTL has three distinct reasons to interact with Wazuh, and the implementation
must keep them distinct:

1. The control plane may connect to the indexer and manager API only to attest
   facts in the admitted realization. This is a startup-fatal runtime
   attestation, not a general health check.
2. Evidence capture reads only the sources and channels declared by the
   admitted scenario. TechVault's SQLi evidence reads the manager alert log;
   its agent-readiness evidence reads the manager and forwarding-agent file
   artifacts. Neither path may query the indexer.
3. Participants may continue to use the Wazuh MCP servers. Their loopback host
   port publications and credential delivery are participant access, not an
   authorization for APTL evidence collection.

The deployment backend's post-start observation is the single owner of Wazuh
native attestation. It records structured, secret-free observations for the
existing RAES observation and exact-concern gate. `Lab` must not perform a
second Wazuh login or reinterpret a successful login as proof of realization.

Pack-declared credentials are scenario fixtures. The admitted pack is their
authority; `.env`, rendered configuration, backend profiles, and workbench
configuration are delivery surfaces only. APTL must not maintain another copy
or classification of those values.

## Existing Contracts to Reuse

### Declaration and realization

- `env_pack_bundle`, RAES parsing, instantiation, and semantic validation are
  the admission boundary. Only the admitted bundle may supply pack-declared
  values and facts.
- `DeploymentRealizationSpec` and `wazuh_cluster_identity()` provide semantic
  node identity. New logic must not rediscover Wazuh from container-name
  literals, profiles, or image strings.
- `_declared_listener_readiness` and `observe_runtime_concerns()` already own
  listener and published-port readback. A manager API probe must not duplicate
  listener attestation.
- `raes_runtime_attestation.observe_techvault_attested_concerns()` and
  `raes_observation.observe_realization()` are the existing path from a native
  observation to the runtime concern set. A missing or mismatched fact must
  withhold the affected concern so the existing RAES exact-concern gate rejects
  the realization and `render_raes_diagnostics()` reports it.
- `WazuhApiProbe`, `ReadinessPolling`, and `curl_safe()` provide the bounded
  transport, phase/category reporting, and secret-safe authentication
  mechanics. Their current authentication-success checks are mechanics to
  reuse, not the attestation contract.

The current boolean `authenticated_readiness` is not sufficient evidence of a
declared fact. It may temporarily be derived as a compatibility projection, but
it must not remain an independent authority or be used to disclose a runtime
concern.

### Evidence

- `capture_registrations`, the exact demand/offer matcher, `WindowedSource`,
  `SourceResult`, and `CollectorStatus` own source identity, channel, media
  type, bounded collection, and loss disclosure.
- `SuricataWazuhSqliSource` owns the composite SQLi correlation contract. Keep
  its existing correlation and typed loss result; replace only the Wazuh source
  operation with a bounded manager alert-log reader.
- `techvault_native_readiness` and `techvault_readiness_probes` already read the
  declared manager roster, manager alert/archive files, and forwarding-agent
  artifacts. They are the incumbents for `wazuh-agent-readiness`.
- Live validation must consume the same admitted native source operation and
  typed source result as capture. It may project that result into its existing
  verification report, but it must not maintain a second manager-log parser or
  an indexer fallback.
- The evidence coordinator and `LocalRunStore` remain the persistence boundary.
  Persist normalized evidence and typed loss, not credentials, request headers,
  or raw API responses.

The legacy `collect_wazuh_alerts()` contract is deliberately not reusable: its
hard-coded credentials, indexer source, and empty-list-on-failure behavior
conflict with the declared source and loss semantics. Remove it rather than
migrating it.

### Credential declaration and delivery

- RAES `RuntimeEnvironmentVariable.value_classification` and `provenance` are
  the canonical classification vocabulary. Do not add an APTL credential enum
  or a parallel key-classification table.
- The exact-pack `ScenarioStartupProvider` is the seam for projecting admitted
  TechVault scenario fixtures into APTL's generic delivery aliases.
  `update_dotenv_values()` remains the validated, atomic `.env` writer.
- `load_dotenv()`, `env_vars_from_dict()`, placeholder validation, and the
  generated-config safeguards from ADR-028 remain the config-shape boundary.
  Pack-fixed aliases are reconciled to the admitted value; a divergent existing
  value is never preserved as an operator override. Diagnostics may name an
  affected key, but never its old or new value.
- `_compose_runtime_config` and `_raes_runtime_environment_observation` already
  distinguish fixture commitments from operator-secret presence. Backend
  implementation profiles describe delivery mechanics; they must not become a
  second source of scenario values or provenance.
- Workbench profiles remain a closed, secret-free alias allowlist.
  `EphemeralCredentialBroker` and the existing private MCP config renderer
  resolve those aliases after admission. Profiles must not embed, classify, or
  log credential values.

Until the pack declares the indexer `admin` and `kibanaserver` plaintexts, the
release-specific compatibility knowledge required to materialize their hashes
belongs behind the exact TechVault adapter in `aptl_techvault`. It must be
content/release qualified, must not claim pack provenance, and must be deleted
when the upstream declaration becomes available. It does not authorize a
generic fallback in core.

## Native Attestation Contract

The backend post-start stage must create one normalized observation for each
declared native fact it is responsible for. The input is the admitted
realization, including semantic Wazuh identity and the declared datastore
service; the output contains stable fact identifiers, expected/observed
summaries, and safe failure categories, but no credentials or raw response
bodies.

The indexer observation covers the declared partitions, templates, and
mappings. It is read-only and compares normalized native state to the declared
facts. Do not reuse the service-search-index materializer as an owner: that
code proves a different RAES content-placement concern. Shared OpenSearch
transport or normalization helpers may be extracted only where their semantics
are genuinely identical.

The manager observation covers manager-native declared facts that require the
API. Declared listeners remain owned by the generic listener observer. A 2xx
login, token issuance, or process liveness is a transport precondition, not an
attested fact.

All native checks share one bounded polling budget. A transport failure,
malformed response, absent fact, or mismatched fact produces a missing or
failed attestation observation. The existing RAES gate then makes realization
fail startup. Do not add a parallel exception hierarchy or an independent Lab
readiness verdict.

No declaration means no control-plane authorization to connect. Selecting a
profile named `wazuh` or finding a familiar container is insufficient.

## Cross-Cutting Security Layers

The implementation must pass every layer below:

1. **Pack admission:** exact pack identity, set digest, schema parsing, and RAES
   semantic gates establish which facts and fixtures are authoritative. Local
   templates and stale `.env` values cannot override this layer.
2. **Classification and shape:** RAES runtime-environment-variable validation
   establishes fixture versus operator provenance. Environment names and
   single-line values pass the existing environment validators; unresolved
   placeholders fail closed.
3. **Filesystem generation:** generated files remain below the ADR-028 managed
   root with containment, symlink, atomic-write, and permission checks. An
   admitted pack artifact, rather than `config/wazuh_indexer/internal_users.yml`,
   supplies the internal-users content. Generated secret-bearing files remain
   excluded from source control and diagnostic attachments.
4. **Effective deployment model:** compose expansion, stateful model validation,
   `DeploymentBackend`, and runtime inspect remain authoritative for containers
   and published ports. Participant ports remain loopback-bound; the issue does
   not justify broader host exposure.
5. **Authentication transport:** continue to use `curl_safe()` or an equivalent
   backend primitive that places Basic/Bearer material in protected temporary
   files or stdin, never URLs, process argv, command text, or logs. The Wazuh
   insecure-TLS exception remains narrowly governed by ADR-034 and must not be
   presented as peer authentication.
6. **Container and process execution:** use `DeploymentBackend` bounded exec and
   stdin-script facilities with fixed argv and capped output. A declared or
   content-qualified adapter may select the manager log path; untrusted scenario
   data must not become an arbitrary host path or shell fragment.
7. **Evidence validation:** exact registered source references, channel, and
   media type precede parsing. NDJSON parsing, time windows, record caps, and
   `SourceResult` statuses make malformed input and missing records explicit.
8. **Attestation and error envelopes:** the RAES concern gate and diagnostics
   own realization failure. Capture diagnostics, verification reports,
   `LabResult`, and startup diagnostics retain their existing scopes. Every
   envelope must contain stable categories and redacted summaries, never secret
   values, auth headers, or raw Wazuh bodies.
9. **Persistence and logging:** use the evidence store and existing redaction
   logger. Persist commitments or normalized facts, not credential material.
   Structured attestation objects must be safe in `repr`, test failures, and
   serialized diagnostics.
10. **Participant delivery:** the workbench alias allowlist, credential broker,
    and private config permissions remain mandatory. Scenario-fixture
    classification does not make a password public or safe to print.

## Extensibility Seam

The native-attestation seam is a declaration-driven observer keyed by semantic
node identity, concern kind, and declared fact identity. Its inputs include the
admitted fact set, declaration-derived endpoint selectors, credential binding,
and a shared deadline/clock; its output is a normalized, secret-free fact set
for the existing RAES disclosure path. Adding a Wazuh version or another
declared partition, template, or mapping should add data or an adapter check,
not another branch in `Lab` or an evidence collector.

The credential seam is the exact-pack startup adapter projecting admitted
scenario fixtures onto generic aliases. A future pack version changes that
projection, not `EnvVars`, the implementation catalog, or workbench profiles.

The evidence seam is a bounded declared-log reader parameterized by semantic
node, content-qualified path, time window, record cap, and predicate. It may be
shared by TechVault capture and live validation, but it must remain in the
TechVault adapter rather than becoming a core Wazuh collector.

## Gotchas and Prohibited Conflations

- Authentication success is not attestation of a partition, template, mapping,
  listener, or manager semantic fact.
- A bound listener is not proof of the API's declared semantics; conversely,
  the manager API must not re-own listener observation.
- Image/content digest compatibility attestation is not observation of native
  runtime state. Both are required where the admitted concern requires both.
- Startup attestation, evidence acquisition, and participant access are three
  separate authorities. A credential or port available to one does not grant
  the others a new purpose.
- A `secret_fixture` is fixed scenario content, not public data. Never emit it.
- `.env` is a local delivery cache, not a declaration source. Do not preserve a
  divergent fixed value, including `API_USERNAME` or `API_PASSWORD`.
- The generated env-pack deployment and the root compose compatibility path
  both require audit. Removing a copy from one does not make the other
  pack-grounded.
- A persisted indexer volume can retain hashes from an earlier realization.
  Normal startup must attest rather than silently mutate it; destructive reset
  remains an explicit recovery action.
- OpenSearch and log content are untrusted and potentially large. Bound response
  size, line count, and time. Do not log raw failures or response bodies.
- A bounded tail may begin with a partial NDJSON line. Handle that boundary
  explicitly; malformed input or an absent correlated record must not become a
  successful empty result.
- Use one outer deadline. Nested retry loops can multiply startup and capture
  budgets.
- Tests for forbidden credential copies should derive comparison values from an
  admitted test pack or use synthetic canaries; do not reintroduce the real
  values as test constants.

## Non-Goals and Boundaries

- Do not remove participant Wazuh MCP access, indexer access, or the loopback
  host publications required by those clients.
- Do not prohibit all indexer connections. APTL's control plane may connect for
  declared realization attestation; evidence capture may not.
- Do not redesign the credential broker, introduce a new secret store, or add a
  second credential-classification model.
- Do not create a general OpenSearch plugin framework or merge Wazuh datastore
  attestation with RAES service-search-index materialization.
- Do not solve the upstream pack schema gap tracked by OpenRAE/env-packs#392.
  Keep the smallest exact-TechVault compatibility projection until upstream
  supplies the missing facts.
- Do not widen the ADR-034 TLS exception or treat disabled verification as an
  acceptable trust model outside its existing local-lab boundary.
- Do not change unrelated SOC credentials, collectors, or scenario behavior.
