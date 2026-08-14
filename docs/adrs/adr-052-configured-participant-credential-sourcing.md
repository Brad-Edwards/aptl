# ADR-052: Configured Participant Credential Sourcing

## Status

accepted

## Date

2026-08-12

## Context

Before issue #856, APTL's installed-participant path read `ANTHROPIC_API_KEY`
or `CODEX_API_KEY` from the parent process environment in
`build_selection_provider()`. The child environment was narrow, but the parent
source was implicit. The former `EphemeralCredentialBroker` then copied a
static value into an in-memory mapping and deleted that mapping after use.

That behavior proves temporary APTL possession and local reference cleanup. It
does not prove that the value was issued for this run, is short-lived, is
delegated, can be renewed, expires, or is revoked upstream. It also does not
prove that an installed provider ignored a saved product login, user keychain,
home-directory credential, cloud SDK default chain, metadata service, or
workload-identity socket.

This ADR selects a provider-neutral credential-sourcing boundary for issue
#856. It supersedes only the participant-credential sourcing and lifecycle
wording in ADR-049 and the issue-557, issue-821, issue-858, and issue-862
preflights. Their appliance, participant, model-selection, process, and RAES
boundaries remain unchanged.

## Terminology

These terms are not interchangeable:

| Term | Meaning in APTL |
| --- | --- |
| Credential source | The configured mechanism and locator from which APTL acquires credential material. |
| Acquisition | The act of resolving one configured source for one provider/run. |
| Delivery or binding | The provider adapter's mapping of acquired material to a provider-supported input channel. |
| Temporary possession | APTL or its child holds credential material for a bounded local interval. This says nothing about upstream validity. |
| Expiry | An issuer-enforced `not_after` after which the credential is invalid. Only issuer/resolver metadata may establish it. |
| Cleanup | APTL stops children and removes its references or private files. Cleanup does not invalidate copied material elsewhere. |
| Revocation | The issuer or authoritative broker invalidates the credential before or independently of expiry. Clearing memory is not revocation. |
| Lease | An issuer-backed lifecycle with an identifier and defined expiry, renewal, and/or revocation operations. A copied static value is not a lease. |
| Delegation | An authorization service preserves an actor/subject relationship while granting constrained authority. Copying another principal's API key is not delegation. |

Externally visible claims and evidence use these meanings. “Ephemeral” may
describe an APTL process, directory, or possession interval, but not a
credential unless the credential itself has an authoritative expiry.

## Threat Model

The design assumes the operator who edits `aptl.json` may select an approved
credential source, but credential values and provider output remain secret or
hostile. It addresses:

- stale or unintended credentials inherited from a shell, IDE, `.env` loader,
  user login, keychain, home directory, cloud CLI, SDK default chain, metadata
  service, projected token, or workload socket;
- one installed provider receiving another provider's credential;
- a provider's own precedence rules overriding APTL's intended source;
- missing, placeholder, malformed, oversized, unavailable, expired, or
  internally inconsistent source results;
- credential exposure through config display, process argv, prompt stdin,
  filesystem paths, logs, exceptions, provider stdout/stderr, telemetry,
  readiness evidence, run provenance, or exports;
- cleanup skipped on partial launch, inventory, request, timeout, parse, or
  persistence failure; and
- evidence that calls cleanup “revocation” or static possession a “lease.”

The boundary does not defend against a compromised kernel, root in the
management compartment, ptrace-equivalent access to the credential-bearing
process, or an upstream issuer that misstates its token semantics. The
supported appliance must provide the process/user/PID and egress isolation
needed for any stronger isolation claim; a developer-local run cannot inherit
that claim merely by using the same Python classes.

## Research Considered

The following established patterns informed the decision:

| Pattern and primary source | Relevant property | APTL conclusion |
| --- | --- | --- |
| [Claude Code authentication precedence](https://code.claude.com/docs/en/authentication) | Claude can select cloud credentials, bearer/API-key environment variables, an `apiKeyHelper`, OAuth tokens, or saved login state in a defined order. | Supplying one environment variable is insufficient proof unless APTL also isolates or disables every ambient source applicable to the selected mode. A provider helper is a viable future delivery integration, not permission for arbitrary configured shell. |
| [OpenAI Codex authentication](https://developers.openai.com/codex/auth) | Codex supports ChatGPT login, API-key login through stdin, local caching under `CODEX_HOME`, credential-store selection, status, and logout. | APTL must use a private provider home/store and a provider-supported non-argv bootstrap or direct channel. A user's normal Codex login is not an implicit qualification source. |
| [OpenAI workload identity federation](https://developers.openai.com/api/docs/guides/workload-identity-federation) | External workload identity is exchanged for a short-lived OpenAI access token with issuer, audience, subject mapping, and expiry semantics. | Federation is a first-class future source kind. Its evidence may claim exchange and expiry only after validating authoritative response metadata; it must not be flattened into “API key.” |
| [AWS standardized credential providers](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html) | SDK chains search environment, login/profile, process, container, web identity, and instance metadata sources and refresh temporary credentials. | APTL must select an exact provider/source mode, not invoke an unrestricted default chain. Refresh belongs to the selected resolver/provider contract. |
| [Google Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) | ADC searches an environment-selected file, a well-known user file, then attached-service metadata. | Search chains are convenient but violate source provenance unless configuration selects and isolation admits exactly one branch. |
| [Azure credential-chain guidance](https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication/credential-chains) | Microsoft recommends deterministic credential implementations in production because default chains can change with host environment. | Use a specific configured credential implementation; do not treat `DefaultAzureCredential` as a source kind. |
| [Kubernetes projected service-account tokens](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) | Projected tokens carry audience and expiry, rotate, and can become invalid when the bound object is deleted. | A projected-token resolver can support bounded audience/expiry evidence, but cleanup, expiry, and object-bound invalidation remain separate facts. |
| [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/) | Workloads request short-lived X.509/JWT SVIDs, including audience-bound JWTs, through an authenticated local workload endpoint. | A workload-identity resolver should select the endpoint, identity/audience constraints, and returned SVID explicitly; socket presence alone is not authority. |
| [OAuth 2.0 Token Exchange, RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) | Token exchange distinguishes impersonation from delegation and can constrain resource, audience, scope, and lifetime. | APTL uses “delegation” only when the issuer's protocol and evidence actually preserve those semantics. |
| [Vault lease, renewal, and revocation](https://developer.hashicorp.com/vault/docs/concepts/lease) | Dynamic secrets have lease identifiers, TTLs, renewal, and authoritative revocation; Vault KV static secrets do not. | “Lease” is reserved for a resolver that returns and manages those facts. Reading a static secret from Vault does not become a lease because Vault transported it. |

## Options And Tradeoffs

### Ambient provider/default chains

Retaining provider-native default discovery minimizes APTL code, but makes the
selected account and source depend on host state. Evidence cannot distinguish
an environment key from a saved login or metadata identity reliably. Rejected.

### Raw secret values in `aptl.json`

This is explicit and reproducible but turns the first-party non-secret config,
`aptl config show`, config provenance, source control, and support artifacts
into secret surfaces. It violates ADR-029 and is rejected.

### Configured environment-variable source

The config names exactly one parent environment variable. APTL reads only that
name, validates the value without logging it, and passes only the provider
adapter's required delivery fields to an isolated child. This is portable and
is the smallest defensible replacement for current behavior. It still carries
a static credential in parent and child memory/environment, offers no issuer
expiry or revocation semantics, and can be inspected by sufficiently
privileged sibling processes. Accepted as the initial source kind with those
limitations made explicit.

### Configured private file or OS credential store

Descriptor-relative/no-follow reads or an OS keyring reduce shell-environment
exposure, but add platform behavior, path/ownership policy, store selection,
and provider delivery concerns. They are viable future source kinds after
their resolver contracts and isolation tests exist. No implicit home-directory
or default-keyring search is allowed.

### Configured helper or external secret broker

A fixed, code-owned helper/broker integration can retrieve rotating or dynamic
credentials and return lifecycle metadata. Allowing arbitrary command/argv,
shell strings, or provider-owned config fragments would instead create a code
execution and secret-exfiltration surface. Viable only as a named resolver
with fixed executable identity, bounded I/O, strict output, and no fallback.

### Workload identity and federated token exchange

This offers strong provenance, audience, expiry, and sometimes revocation or
object-binding properties without a long-lived provider key. It depends on an
issuer, workload identity, token exchange, clocks, network policy, and the
installed provider accepting the resulting credential. Accepted as the
preferred future production source where the deployment and provider support
it, not as a mandatory dependency for developer-local static-key use.

### Model gateway

A gateway can retain upstream provider credentials server-side and issue a
seat/run-scoped gateway credential with centralized audit and revocation. It
also becomes operated infrastructure and changes the authenticated endpoint.
It is a viable configured provider/backend binding, not a universal local
credential store and not a silent substitute for direct-provider mode.

## Decision

### Configuration is the sole source authority

Add one strict, non-secret credential-source selection beside
`ExperimentSettings.participant_models` in `AptlConfig`. The shape is a closed
provider map whose entries contain a discriminated source descriptor. It has
no default and contains no raw credential, provider argv, arbitrary command,
environment map, URL, or fallback list.

The initial descriptor is equivalent to:

```json
{
  "experiment": {
    "participant_credential_sources": {
      "claude": {
        "kind": "process-environment",
        "variable": "APTL_PARTICIPANT_CLAUDE_CREDENTIAL"
      },
      "codex": {
        "kind": "process-environment",
        "variable": "APTL_PARTICIPANT_CODEX_CREDENTIAL"
      }
    }
  }
}
```

The exact field names become part of the strict Pydantic contract. The
important invariants are the closed provider keys, discriminated kind, bounded
locator, absent raw value, and absent default. A config may omit entries so
deterministic workflows remain credential-free; selecting an installed
provider without its valid source entry is fatal before executable launch.

`load_config()` validates descriptor shape. Source resolution then reads
exactly the configured variable. It does not try the provider-native alias,
`.env`, a user login, a home file, a keyring, cloud CLI, SDK chain, metadata
endpoint, or another configured provider. Empty, placeholder, NUL-bearing,
oversized, unavailable, expired, or inconsistent results fail closed through
the existing workbench/readiness error boundaries without including material.

### Source acquisition and provider delivery remain distinct

`src/aptl/workbench/credentials.py` and its incumbent
`EphemeralCredentialBroker` remain the single credential-binding owner; no
second broker or exception hierarchy is added. The configured resolver and its
secret-free evidence live in `participant_source_binding.py`, outside the
generic profile-binding API. Their acquisition seam is:

```text
(validated source descriptor, requested credential contract,
 provider id, run id) -> acquired secret payload + lifecycle facts
```

The closed installed-provider mapping in
`participant_readiness_provider.py` continues to own provider id, adapter,
executable policy, and required credential contract. The adapter alone owns
the provider-native delivery channel. A source environment-variable name is
never assumed to be the child's provider-native alias.

The child receives a newly constructed minimal environment or private
credential store. Provider-native aliases not supplied by the selected
binding are absent. User/home product state is replaced with a private empty
home/config root and ignored with supported flags. The initial
process-environment source neither enables cloud metadata endpoints or workload
sockets nor claims that process-level controls make them unreachable. Any
supported environment that requires a stronger exclusion claim must enforce
and verify the applicable appliance/network negative controls. If an installed
provider cannot demonstrate its required adapter controls, APTL fails
qualification rather than making the claim.

Secrets never enter process argv, prompt stdin, URLs, filenames, config JSON,
or provider-visible task content. A provider-supported stdin bootstrap or
private store may be used when direct environment delivery is unsupported;
the resulting store is provider-run-private state, not the credential source.

### Lifecycle facts are data, not inferred adjectives

Each acquisition carries a secret-free lifecycle description from its source
kind: source kind/resolver version, acquisition outcome/time, authoritative
expiry when one exists, renewal support/outcome, upstream revocation
support/outcome, and local cleanup outcome/time. Static process-environment
sources report expiry `unknown`, renewal `unsupported`, upstream revocation
`unsupported-by-aptl`, and cleanup limited to local possession.

An acquisition with authoritative expiry must remain valid for the bounded
launch/request/cleanup window or fail before use. Refresh or renewal is owned
by that resolver/provider contract and cannot silently switch source kinds.
Cleanup runs on every exit path, after child process-group termination, and
removes private provider stores and in-memory references. It does not claim
secure erasure of Python strings, kernel process-environment copies, or
upstream invalidation.

### Evidence is a projection of the one acquisition

Extend the existing participant readiness/qualification and participant
provenance builders with one shared secret-free credential-binding projection;
do not create provider-specific report schemas or a parallel run archive. The
projection records:

- provider and run identity;
- source kind and resolver contract/version;
- a canonical digest of the validated non-secret source descriptor, not the
  secret value, plus its config field reference;
- provider-native delivery kind/contract, without paths or values;
- the exact adapter isolation controls applied and verified;
- acquisition, expiry/renewal/revocation facts using `known`, `unknown`,
  `unsupported`, `not-requested`, `succeeded`, or stable failure codes; and
- local cleanup and isolation proof outcomes.

It never records a secret value, prefix, suffix, length, secret-derived hash,
auth header, provider response, account/project identity, home path, helper
stdout/stderr, lease id, access token claims, or raw exception. General safe
config provenance continues to exclude credential locators; the descriptor
digest lets an operator holding the applicable config correlate the evidence
without publishing the locator.

Readiness evidence must survive acquisition or launch failure before turn
zero. Cleanup outcome is captured after provider close, so a successful model
request with failed cleanup is not a fully passing qualification. Published
schema versions are bumped at their existing owners rather than silently
changing a `v1`/`v2` meaning.

## Cross-Cutting Passage And Canonical Incumbents

| Layer | Required passage and incumbent |
| --- | --- |
| Operator ingress | `aptl lab participant-readiness` continues through `resolve_config_for_cli()` and `load_config()`. There is no new API route, secret CLI flag, or provider-selected source. A future API must reuse authenticated config DTO conventions and this same model. |
| Strict config shape | `ExperimentSettings`, `AptlConfig`, Pydantic `extra="forbid"`, strict scalar constraints, and ADR-025 own provider keys, source discriminators, and bounded locators. `aptl config show` remains safe because values are absent. |
| Installed-provider selection | `build_selection_provider()`, `_launch_adapter()`, `installed_version()`, and the issue-862 closed provider/model mapping own the provider, model, executable, adapter, and requested credential contract. Source config cannot select argv, executable, tools, endpoint, or model. |
| Credential acquisition | `aptl.workbench.participant_source_binding`, the incumbent `EphemeralCredentialBroker`, `WorkbenchCredentialError`, `contains_placeholder()`, and the existing per-provider/run cleanup lifecycle own resolution and binding. Do not widen Wazuh-oriented `EnvVars` or add a second broker. |
| Provider delivery | `ManagedAgentAdapter`, `ClaudeCodeManagedAgentAdapter`, `CodexManagedAgentAdapter`, `AgentLaunch`, and their launch/close handles own provider-native aliases, stdin/private-store bootstrap, and clearing. Provider output never defines the source used. |
| Product/user-state isolation | `_prepare_work_dir()`, private `CODEX_HOME`, Claude bare/config isolation, fixed child environments, signed appliance settings, and provider-version qualification own product-state exclusion. Add private `HOME`/XDG/provider roots or equivalent isolation where required; absence from `env` alone is not proof that `getpwuid()`, a keychain, or metadata service is unreachable. |
| OS/process exposure | `_admitted_executable()`, `BoundedProcessRunner`, fixed argv, `shell=False`, stdin task delivery, combined output bounds, process groups, timeouts, private `0700` state, `0600` no-follow files, appliance PID/user isolation, and egress allowlisting remain mandatory. Credential material is never argv or a URL. Child environment delivery is evidence of possession, not strong same-user isolation. |
| Provider/config validation | Adapter provider/model matching, exact response schema, strict result parser, and actual bounded request validate the configured pair. Credential format is not guessed from a secret prefix; provider rejection becomes a stable generic classification. No retry under another credential or source. |
| RAES boundary | Existing participant apparatus, decision-surface delivery, compact selection, exact candidate membership, `AptlParticipantRuntime`, and RAES admission remain unchanged. Credential source selects authentication only and grants no action, visibility, implementation identity, or actor provenance. |
| Error envelopes | Reuse `WorkbenchCredentialError` and `AgentExecutionError` internally, then existing readiness reports and RAES diagnostics. `get_logger()` and `redact()` apply before logs/diagnostics; raw Pydantic secret values cannot arise because config carries locators only. Do not add a credential-wide exception taxonomy. |
| Persistence and observability | `ParticipantReadinessReport`, qualification/control evidence builders, participant provenance provider, `RunStorageBackend`, `LocalRunStore` JSON/JSONL/create-once methods, ADR-029 redaction, and exporter packaging remain the owners. Never use opaque `write_file()` for credential-bearing output or make exporter the first filter. |
| Appliance/network policy | ADR-049, `ApplianceBoundaryPolicy`, boundary gates, management-zone placement, exact-authority egress, and guest replacement determine supported isolation. A selected metadata/workload endpoint is an explicit flow; other credential-service exclusions may be claimed only when the applicable appliance controls are enforced and verified. Process-level evidence does not imply that claim. |

The repository surfaces in scope are `aptl.json`; `src/aptl/core/config.py`;
the config CLI and safe-config provenance projection;
`src/aptl/validation/participant_readiness_provider.py`, readiness and
qualification models/builders; `src/aptl/workbench/{credentials,agent,
codex_agent,participant_source_binding,process,runtime,bootstrap}.py`;
participant apparatus/control
evidence and provenance; runstore/redaction/logging; appliance boundary and
launch assembly; the bounded-participant runbook; and their existing config,
workbench, runtime, readiness, provenance, runstore, redaction, and appliance
tests. SDL, MCP tool schemas, deployment backends, Compose topology, and the
web frontend are not credential-source authorities.

## Extensibility

The seam is the code-owned resolver registry inside the existing credential
owner, parameterized by source kind and requested credential contract. A new
source kind adds one strict descriptor model, one resolver, lifecycle evidence
mapping, and isolation/negative tests. It does not add provider-specific config
fields, change RAES contracts, or edit every adapter.

A new installed provider adds one closed provider binding that declares its
credential contract and delivery adapter. It reuses all existing source kinds.
A new cloud backend or gateway explicitly selects its routing/backend binding
and one compatible source; it cannot activate a default SDK chain. Structured
credential sets, refresh, federation audiences/resources/scopes, and
authoritative revocation belong in the resolver result and provider contract,
not in raw environment maps.

## Consequences

### Positive

- Operator intent, source provenance, provider delivery, and lifecycle claims
  become independently testable.
- The immediate environment-based use case stays simple while unselected
  parent variables and provider user configuration are excluded by explicit,
  testable adapter controls.
- Static, dynamic, gateway, cloud, and federated sources can coexist without
  changing RAES participant semantics or duplicating adapters.
- Evidence can prove exactly what APTL did without retaining credential
  material.

### Negative And Risks

- Existing installed-provider commands fail until a source entry is configured;
  there is deliberately no compatibility fallback.
- Static environment delivery remains visible to sufficiently privileged local
  processes and has no APTL-controlled expiry or upstream revocation.
- Provider CLIs change authentication precedence and storage behavior across
  versions, so live qualification must pin and retest the exact adapter controls
  on which its source-binding evidence relies.
- Dynamic and federated sources require clock, issuer, audience, refresh,
  network, and cleanup handling that the initial environment source does not.

## Non-Goals

- Do not build a general secret manager, replace an organization's Vault/KMS,
  or promise secure erasure of immutable language/runtime strings.
- Do not move lab/SOC `.env` values into participant credential config or widen
  `EnvVars` into a generic secret bag.
- Do not redesign participant selection, RAES lifecycle/action contracts,
  model selection, MCP profiles, deployment backends, runstore layout,
  appliance attestation, or web authentication.
- Do not require federation for local development or claim the static
  environment source is federated, delegated, renewable, expiring, or
  revocable.
- Do not make provider credentials part of participant apparatus identity or
  actor provenance. Authentication provenance is a separate evidence concern.
- Do not expose credential configuration to the participant or allow scenario
  SDL, prompts, provider output, or CLI flags to choose it.

## Anti-Patterns

- Falling back to `ANTHROPIC_API_KEY`, `CODEX_API_KEY`, `OPENAI_API_KEY`, a
  saved login, `~/.aws`, ADC, Azure CLI, keychain, metadata service, or another
  provider because the configured source failed.
- Treating a minimal child environment as proof that home, keychain, SDK, Unix
  socket, or metadata credentials are unreachable.
- Calling dictionary deletion, process exit, private-directory removal, guest
  reset, or expiry “revocation” without an upstream invalidation operation.
- Calling a static API key copy an ephemeral lease, delegated credential, or
  run-scoped authorization.
- Putting secrets or secret-derived hashes in `aptl.json`, Pydantic errors,
  argv, stdin prompts, URLs, filenames, config digests, evidence, logs, or
  traces.
- Adding a provider-specific `claude_credential_source`/`codex_credential_source`
  schema, a second broker, a second redactor, or a second readiness report.
- Allowing arbitrary helper commands, shell strings, executable paths,
  environment maps, credential-chain lists, URLs, or provider config fragments
  in first-party configuration.
- Recording a passing lifecycle/isolation claim when acquisition succeeded but
  required adapter controls, process teardown, private-store cleanup, or
  evidence publication failed, or generalizing those controls into an
  unverified metadata, socket, keychain, or network exclusion claim.

## References

- [ADR-025](adr-025-strict-first-party-config-schema.md): strict first-party
  configuration.
- [ADR-029](adr-029-control-plane-secret-handling.md): secret classification,
  redaction, persistence, logging, and OS exposure.
- [ADR-044](adr-044-raes-aligned-run-reproducibility-record.md): existing
  participant/run provenance and evidence boundaries.
- [ADR-049](adr-049-sealed-disposable-lab-appliance.md): supported appliance
  placement, isolation, egress, reset, and secret injection.
- [Issue #557 preflight](../architecture/issue-557-participant-implementation-binding-preflight.md):
  installed-provider and RAES participant boundary.
- [Issue #862 preflight](../architecture/issue-862-explicit-participant-model-selection-preflight.md):
  explicit provider/model selection and evidence boundary.
- GitHub issue #856.
