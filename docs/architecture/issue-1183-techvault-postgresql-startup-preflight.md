# Issue #1183: TechVault PostgreSQL Startup Preflight

The supplied issue is the contract; no formal requirement is attached.
This note sets design guardrails, not an implementation plan. Existing ADR-029,
ADR-046/051, ADR-037, and ADR-060/061 already establish the relevant boundaries;
no new ADR or framework is needed.

## Decision And Current State

Keep database realization in the exact-content-qualified
`TechVaultStartupProvider.realize_runtime()` and its existing `database.py`
helper. Generic materialization owns SQL delivery; the adapter owns the native
PostgreSQL behavior needed to make that admitted content usable. Do not add a
TechVault branch to core, put infrastructure repair in `seed-prime.sh`, or
change the portal to suppress its connection failure.

This checkout already contains that hook and five passing database tests. It
is a starting point, not proof of the issue's complete acceptance. The released
`raes-env-packs==6.2.0` TechVault bundle qualifies as version `0.1.1`, set digest
`sha256:df00ea2a2672864ad8c711a3eab3a8a7bffff4db058b4a9acde032a61b2a1504`.
Its typed runtime declares one PostgreSQL service, `0.0.0.0:5432`, the scenario
database and login role `techvault`, and an internal network `172.20.2.0/24`.
Its exact artifacts deliver `/opt/db-init/01-schema.sql` and
`/opt/db-init/02-seed-data.sql`; neither contains transaction-control statements.
The runtime has no DB/webapp environment entries or typed PostgreSQL HBA policy.
The adapter's subnet-scoped trust rule is compatibility behavior, not a
pack-declared authorization observation. Do not invent an upstream field or
claim pack provenance for it.

The released pack declares Wazuh-agent state for `db`, but no PostgreSQL data
persistent volume. Repeated realization of the same surviving run must preserve
its data. PostgreSQL service restart, container restart, and `aptl lab stop`
are different: the latter uses Compose `down` and removes containers. Do not
claim database retention across container removal. Such retention requires an
explicit pack/stateful-contract change, beyond this startup repair.

## Canonical Owners And Required Passage

| Layer | Incumbent and design obligation |
| --- | --- |
| Pack identity, paths, and integrity | `core/scenario_bundle.py`, `_pack_staging.py`, `utils/pathsafe.py`, env-packs `validate_pack()`, `validate_pack_content_manifest()`, and `resolve_pack_artifact()`. Consume the admitted version/digest and exact artifacts. Guest destination paths are not host source paths. Never edit staged SQL, fall back to checkout assets, or create another manifest/hash/parser scheme. |
| Scenario shape and admission | RAES parser/strict `RuntimeConfiguration`, `RuntimeManager.plan()`, `AptlProvisioner`, `interpret_provisioning_plan()`, `raes_realization_envelope.py`, and blocking diagnostics. Reuse typed database, role, listener, topology, and placement contracts. Validate the complete supported selection before mutation; reject missing, ambiguous, or unsupported declarations rather than guessing from names or installed packages. |
| Adapter qualification and lifecycle | `backends/scenario_startup.py`, `_scenario_startup_runtime.py`, `scenario_runtime_hooks.py`, and `deployment/_compose_post_start.py`. Reuse the admitted selection. Current order is networks/health, traffic mirrors, application providers, scenario runtime, forwarding agents, listeners, authenticated readiness, orchestration, accounts. Preserve log realization before database work and fail startup on a required DB failure. Do not introduce another retry/start workflow or move the repair after the listener gate. |
| Native configuration and OS effects | `aptl_techvault/log_source_support.py::_postgres_cluster`, `log_sources.py`, and `DeploymentBackend.container_exec()` / `container_exec_with_input()`. Share cluster discovery and preserve existing logging settings. Resolve the owned container through the backend, which checks workspace/project ownership; local and SSH Compose use the same commands. No direct Docker subprocess, daemon-wide lookup, host PostgreSQL edit, or container recreation. |
| Durable config and environment shapes | Strict `AptlConfig`, `_scenario_environment.py`, `valid_environment_variable_name()`, `core/env.py::{load_dotenv,validate_required_env,find_placeholder_env_values}`, and `_raes_runtime_environment_observation.py`. This issue needs no new `aptl.json` or `.env` knobs. Preserve pack-owned portal bindings and fixture classification; do not add an arbitrary options map, credential defaults, transport-key override, or bypass. Any future declared binding must pass these incumbents before mutation. |
| Network policy and exposure | Admitted network/ACL realization, `_declared_listener_readiness.py`, `_raes_runtime_network_observation.py`, and `_runtime_concern_excess.py`. Guest `0.0.0.0` is the declared DB socket, not authorization to publish host port 5432. Restrict HBA access to the admitted internal CIDR and selected application database/role; preserve loopback/native rules. Add no host mapping, wildcard HBA, IPv6 access, firewall bypass, extra capability, or Docker socket. VM containment remains ADR-060/061's outer boundary. |
| Authentication and secret transport | Keep participant portal authentication and its authored SQL injection intact. Add no HTTP/MCP route; operator `verify_token`, `WebAuthSettings`, and `BFFMiddleware` Host/session/CSRF gates remain authoritative. ADR-029, backend stdin, and `utils/curl_safe.py` cover secret-bearing commands/HTTP. Never put passwords, SQL seed bodies, tokens, or cookies in host/guest argv, URIs, logs, inspect dumps, traces, or error responses. Fixed nonsecret catalog queries may use argv; execute seed artifacts by path. |
| Failures and observability | `BackendTimeoutError`, existing provider error normalization in `scenario_runtime_hooks.py`, bounded failure lists, `_failure_result()`, `LabResult`, RAES `Diagnostic`, `get_logger()`, and `redact()`. Retain safe stage/reason and exit classification for selection, native config, role/database, bootstrap, and web verification failures. Transport exceptions and timeouts must fail closed. Return no raw exception, command output, SQL, config, or HTTP body, and add no exception/result hierarchy. |
| Runtime proof and persistence | `raes_observation.py`, `raes_runtime_attestation.py`, `RuntimeSnapshot`, and `LocalRunStore` redaction/path rules. Exact artifact/config attestation does not prove an initialized database. Keep independent native/web proof and normal RAES observation; never echo the declaration as newly observed state or change pinned concern digests to conceal drift. Use existing evidence storage, not a bootstrap ledger or inventory subsystem. |

## Native State And Idempotence Guardrails

- Discover the actual supported cluster/version, effective port and config/HBA
  locations; do not derive package version from an authored log filename or
  assume `/etc/postgresql/<version>/<cluster>/pg_hba.conf` is effective. Reuse
  and strengthen the shared cluster validator as needed: its character regex
  alone does not exclude `.`/`..` path segments or leading-option names.
- Treat HBA as ordered policy. Appending an exact line proves neither validity
  nor that an earlier rule permits the client. Preserve unrelated rules and
  metadata, validate effective rules, and verify the selected route as the
  application role. Use safe quoting/positional arguments or stdin for native
  transformations. Avoid repeated appends and unconditional restarts; reload
  or restart only for changed settings that require it, with bounded readiness
  readback. Share the existing PostgreSQL logging owner so repairs do not undo
  its collector/path settings or cause avoidable restart races.
- Reuse narrowly validated SQL identifiers and deterministic `psql` behavior
  (`-X`, stop on SQL errors). Distinguish failed/invalid catalog output from
  confirmed absence. Initialize the selected login role/database ownership
  without gratuitous privilege grants or password rotation; verify existing
  incompatible state and report it rather than silently rewriting a run.
- Run the exact schema then exact seed in one error-stopping transaction under
  the application role. Role/database creation is outside that transaction;
  interrupted bootstrap must leave a classified, recoverable state. Preserve
  authored constraints, values, ownership, and sequence state. Do not copy the
  schema into Python, rewrite inserts as upserts, reseed, drop, truncate, or
  reset volumes to obtain a pass.
- Initialization identity must distinguish never-initialized storage from an
  existing run. An empty public schema or zero users is insufficient: a
  participant can delete data or objects. Any necessary completion evidence
  must share the database's retention/reset boundary, identify the qualified
  artifacts without secret bytes, and become authoritative only with successful
  bootstrap. Reuse native metadata/persistence rather than adding application
  tables, a migration framework, or a host-only marker that outlives its DB.
  Serialize concurrent bootstrap attempts; a timeout after commit requires
  readback before retry. Ambiguous pre-existing state fails without reseeding.
- Fresh initialization needs schema/seed correctness proof. Restart verification
  must not require the original row count, exact current table set, or immutable
  participant data. The current `_verify_seed()` and `_portal_can_query()`
  require users to remain populated, and `_ensure_objects()` infers bootstrap
  eligibility from an empty schema; those predicates do not cover this boundary.
  A release-specific fresh-state oracle is not a second schema authority.

## Verification, Extensibility, And Boundaries

Web verification must use the delivered portal's real client/configuration,
including resolution of `db`, rather than a local superuser socket or an
independent hardcoded DSN. It must explicitly check outcomes, close connections
on every path, and bound connection/query time within the existing startup
budget. Reuse `core/services.py::wait_for_service()` for transient readiness
where necessary; deterministic declaration, SQL, and policy failures are not
retryable warm-up. A timeout on the host exec alone does not prove cancellation
of an in-container SQL transaction.

Require separate evidence for (a) a fresh invalid-credentials HTTP POST reaching
the authored response, (b) a participant-equivalent SQLi reaching the intended
portal behavior, and (c) fresh native Suricata SID 1000010/Wazuh rule 303020
correlation. GET `/login`, TCP reachability, a web-tier count query, and alerts
alone do not prove those HTTP behaviors. The incumbent
`evidence/techvault_native.py::trigger_sqli()` discards the response with
`curl -o /dev/null`; curl transport success can include HTTP 500. Its existing
UNION payload is a detection stimulus, not independently a successful exploit
oracle. Reuse `webapp_endpoint()`, the native capture owner, bounded evidence
windows/deadlines, rule identities, and correlation tests. Do not generate a
second uncorrelated attack, fabricate telemetry, edit detection rules, or
reclassify a failing portal as ready. Successful probes must not persist
session cookies or confuse startup-generated traffic with participant activity.

The extensibility seam is the existing qualified adapter plus typed admitted
database/listener/role and network/placement inputs. Pass the selected internal
CIDR, port, container identities, and artifact destinations through that seam
instead of spreading fixed subnet/port/path constants across helpers. Where
the current hook lacks a needed topology/placement fact, use a narrow typed
extension to its existing context; do not reconstruct a second scenario or add
an untyped configuration bag. A new pack digest requires explicit qualification;
unsupported engines, multiple DBs, or authentication postures fail clearly
until supported. Do not build a general database provisioning framework for
that possible future variation.

Focused tests must extend `tests/test_techvault_database.py`, startup-adapter,
log-source, runtime-observation, and native-evidence patterns as relevant. Use
`tests.helpers.techvault_scenario_bundle()` for authoritative declarations and
artifacts. Cover ambiguous/unsafe selections with no mutations, native/catalog
errors and transport exceptions, failed transactional seed/rollback, retry
after uncertain commit, preservation of changed/deleted run data, conflicting
HBA/role state, no-op restart, and failed web verification. Avoid mocks that
return success for every unknown command or assert only shell text. HTTP and
fresh detection acceptance still require disposable-seat/live qualification;
the five existing passing unit tests are not that evidence.

Whole-repository scope includes the canonical bundle and dependency pins;
adapter entry points in `pyproject.toml`; RAES admission/materialization/readback;
generated Compose, ownership and local/SSH exec; guest generic-systemd
PostgreSQL packaging/config; listener/network policy; native log producers and
Wazuh forwarding; portal/native evidence and live gates; lifecycle/reset and
run-store boundaries; and `.ground-control.yaml`, `.gc/plan-rules.md`,
`.pre-commit-config.yaml`, and CI. Local checks stay targeted via
`tools/run-targeted-tests.sh` and staged `pre-commit run`; full suites/coverage
belong to CI. Compose/Dockerfile/`config/` edits trigger the existing clean-lab
gate, not a substitute ad hoc smoke.

Non-goals are portal refactoring/hardening, changing intentional vulnerabilities
or seeded data, new APIs/DTOs/schemas/exceptions, upstream RAES/pack redesign,
database migrations or expanded persistence, new internal isolation, image
publication, and issue/requirement/PR lifecycle actions. This preflight changes
guidance only; implementation and live qualification remain downstream.
