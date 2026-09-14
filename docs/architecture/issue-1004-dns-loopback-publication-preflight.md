# Issue #1004 DNS Loopback Publication Preflight

This note fixes the architecture boundary for issue #1004. It is design
guidance, not an implementation plan. No new ADR is needed: ADR-034 owns the
loopback-first host-exposure policy, ADR-046 owns scenario-declared published
ports and exact runtime readback, and ADR-036 owns endpoint discovery from
observed runtime inventory.

## Boundary Finding And Decisions

The repository has two DNS declarations with different roles. They must agree,
but they are not interchangeable:

- `docker-compose.yml` contains a compatibility `dns` service and is the
  canonical source inspected by the checked-in Compose host-port resolver. In
  the default dynamic realization that service is scaled to zero.
- The default `ScenarioSourceConfig` selects the validated `techvault` env-pack.
  Its `runtime.network.published_ports` declaration is the desired-state
  authority for the image-free DNS node that actually runs. APTL stages the
  installed pack, validates its exact inventory and digests, lowers its typed
  runtime declaration, and invokes Docker directly for that node.

Changing only the Compose stub can therefore make a source-level policy test
pass while the default running lab still binds every host interface. The
shipped result must carry the same `127.0.0.1:5353 -> 53` decision for TCP and
UDP in both applicable declarations. The default env-pack must come from a
compatible pinned release containing that declaration; never patch an ignored
`.aptl/staged-packs` copy or add an APTL-side override of validated scenario
content.

The bind address, host port, container port, and transport protocol remain four
separate facts. `runtime.network.published_ports` owns host exposure;
`Node.services` owns container-facing service identity and cannot imply a host
publish. BIND may continue listening on the node's container interfaces so the
DMZ, internal, and security networks can use it. Host loopback publication must
not be implemented by changing `named.conf` to listen only inside the
container's loopback namespace.

`APTL_DNS_HOST_PORT` remains a port selector for the checked-in Compose
compatibility declaration only. The default env-pack authors an exact host port
and does not consume that Compose environment variable, so current user guidance
must not claim the variable remaps the dynamically realized DNS node. Do not add
an `APTL_DNS_HOST_IP` string or a second DNS exposure schema. A custom authored
scenario may explicitly declare a non-loopback `host_ip`; that is the existing
reviewable opt-in and must be documented as exposing an unauthenticated lab DNS
service through Docker-managed packet-filter rules. The built-in TechVault
scenario remains loopback-only. A future product-level remote-operator mode,
including a unified override for an exact scenario host port, belongs in one validated
deployment exposure/parameter policy that lowers to the existing
`RuntimePublishedPort` fields, not in per-service environment variables.

The issue does not change port-conflict semantics. Checked-in Compose
convenience ports use `aptl.core.host_ports` and may be remapped through their
existing environment variables. Scenario-declared exact host ports use
`published_port_conflicts()` and fail closed rather than being silently
rewritten. Documentation and endpoint output must not claim that a Compose-only
environment override changes an immutable env-pack declaration.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Host-exposure policy | ADR-034's Host Exposure Amendment and `LOOPBACK_HOST_IP`; operator/control surfaces default to loopback while deliberate scenario attack surfaces stay separately classified. |
| Default scenario source | `ScenarioSourceConfig`, `resolve_scenario_bundle()`, `env_pack_bundle()`, and the env-packs `validate_pack()` / `validate_pack_content_manifest()` gates. The staged pack is immutable input, not a local edit point. |
| Portable published-port shape | RAES `RuntimePublishedPort` under `runtime.network.published_ports`. Do not add a DNS DTO, Compose-shaped mirror, or service-derived inference. |
| APTL lowering | `raes_realization_values.published_ports()`, `DeploymentPublishedPort`, and `raes_base_substrate._published_ports()`. Their omitted-address default is already loopback. |
| Docker realization | `_compose_port_realization` for image-backed nodes and `ComposeBaseSubstrateMixin._append_base_ports()` for image-free nodes. Preserve list-form argv and the distinct protocol entries. |
| Conflict policy | `aptl.core.host_ports` for the checked-in Compose compatibility model; `_compose_realization.published_port_conflicts()` for exact scenario declarations. Do not merge these workflows accidentally. |
| Runtime proof | `raes_runtime_observation._observe_published_ports()` and `_runtime_concern_excess` exact scope matching over Docker `HostConfig.PortBindings`. A wildcard realization must not satisfy a loopback declaration. |
| Local discovery | Backend runtime inventory, `ContainerSnapshot.ports`, `live_resolved_ports()`, and ADR-036 endpoint projection. Runtime facts, not a hardcoded host port or the Compose stub, remain the observation source. `_binding_to_resolved_port()` must not replace Docker's observed `HostIp` with the matching Compose `PortSpec.host_ip`; that would make discovery conceal a broader runtime bind. |
| Results and logging | `BackendSeedError`, RAES diagnostics, `LabResult`, `StartupDiagnostic`, `get_logger()`, and existing redaction boundaries. This change needs no exception hierarchy or response envelope. |
| Distribution identity | `_asset_manifest.py`, the pinned dependency/lock files, and participant profile asset-lock digests. A changed bundled Compose artifact must flow through the existing digest chain; `_asset_manifest.py` itself needs no edit while the bundled root set is unchanged. |

## Security And Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| Authentication surface | DNS has no application authentication layer. Loopback is the host-side access boundary; it supplements rather than changes the in-range DNS policy. No API, web session, MCP authorization, or terminal allow-list changes are involved. |
| Secret surface | The host IP and port are non-secret. Keep credentials and generated `.env` data in the existing dotenv/generated-file boundaries; do not serialize an environment mapping or introduce a secret-bearing command. |
| Config and environment shape | `aptl.json` remains the strict Pydantic `AptlConfig` shape with `extra="forbid"`. `.env` continues through `load_dotenv()`, `env_vars_from_dict()`, and placeholder rejection. `APTL_DNS_HOST_PORT` is parsed by the incumbent Compose port resolver only; it neither parameterizes the default env-pack's exact binding nor becomes an unvalidated bind-address escape hatch. |
| Pack and SDL validation | The selected env-pack passes its own inventory/digest gates, then the RAES parser, compiler, planner, and APTL typed lowering. A consumer-side mutation after those gates would invalidate provenance and duplicate policy validation. |
| Compose shape | The compatibility declaration must survive actual `docker compose config` rendering as two long-form entries with `host_ip: 127.0.0.1`, target 53, published 5353, and protocols TCP and UDP. A hand-written YAML parser is not the rendered-model authority. |
| OS/runtime exposure | The image-free path emits two non-secret `docker create/run -p` arguments. Docker inspect must report loopback for both bindings. Docker's firewall/NAT rules make a wildcard bind materially broader even when a host firewall appears restrictive. |
| Runtime policy gate | The existing exact published-port observer checks declared versus realized host IP, host port, container port, and protocol and rejects undeclared or broader bindings. Reuse it; do not infer safety from successful DNS queries or container health. |
| Error envelope | Compose/model failures stay in backend results; materialization failures use `BackendSeedError`; RAES mismatches use its existing diagnostic/apply result; lifecycle failures use `LabResult` and `StartupDiagnostic`. Report bounded service/binding coordinates, never raw inspect payloads, commands, environment, or stderr. |
| Logging and persistence | Existing host-port logs may record service and numeric binding facts. Run evidence retains validated pack identity and the existing runtime concern disclosure. Add no DNS-specific state file, database field, telemetry schema, or persisted duplicate of the mapping. |

The DNS configuration still enables recursion only for the lab subnet while
serving the TechVault zones on all container interfaces. Do not conflate that
in-container query policy with the host publication boundary: a wildcard Docker
publish still exposes an unauthenticated authoritative DNS surface and Docker's
packet-filter path to the LAN.

For `ssh-compose`, `127.0.0.1` means loopback on the remote Docker daemon host,
not on the CLI machine. Do not weaken the binding to preserve a misleading
`localhost` URL. Secure tunnelling or a remote-operator endpoint contract is a
separate design decision.

## Verification Contract

Evidence must cover the actual boundaries rather than repeat the same source
assertion:

- The compatibility model is rendered through Docker Compose and contains
  exactly the TCP and UDP loopback entries. The existing
  `tests/test_docker_compose_port_bindings.py` policy classification remains a
  useful static guard, but its local YAML/variable parser is not runtime proof.
- The validated default env-pack is parsed and lowered through the normal
  scenario path, and its DNS realization contains exactly the same two binding
  facts. Tests must stage the installed pack with `env_pack_bundle()`; ignored
  developer staging directories are not fixtures.
- Extend the existing base-substrate command test, which currently exercises a
  single UDP binding, so the DNS realization proves distinct TCP and UDP
  loopback arguments. The published-port runtime observer continues to reject
  wildcard for a loopback declaration.
- The real-Docker DNS integration test inspects both runtime bindings and keeps
  the existing DNS query/readiness proof. `NetworkSettings.Ports` or
  `HostConfig.PortBindings` is the binding evidence; an in-container
  `dig @127.0.0.1` proves DNS behavior but says nothing about host exposure.
- Local reporting/discovery consumes the observed binding and keeps the two
  protocols coalesced without replacing runtime host IP with a value copied
  from the compatibility Compose file. Its best-effort fallback remains a
  display concern and must not become exposure-policy evidence.

Per `.gc/plan-rules.md`, a `docker-compose.yml` change is not complete until a
clean `aptl lab stop -v && aptl lab start` produces a healthy lab on a fresh
machine. The proof must use a clean locked install so an ambient editable
env-pack or stale `.aptl/staged-packs` tree cannot supply the corrected bytes.

## Gotchas And Anti-Patterns

- Do not treat the scale-to-zero Compose `dns` stub as the live default DNS
  container.
- Do not edit `.aptl/staged-packs`, copy the TechVault SDL into APTL, mutate the
  pack after validation, or add a node-name special case during lowering.
- Do not take an unrelated RAES, env-packs, or MCP major-version migration only
  to acquire this data correction. Use a compatible corrected pack release, or
  treat its absence as an upstream blocker.
- Do not reuse the local short-syntax parser in another test or validator.
  Compose rendering and the RAES typed/readback paths already own those shapes.
- Do not use `ContainerSnapshot` endpoint parsing as the exposure validator;
  its endpoint projection intentionally reduces a binding to a reachable host
  port and is not the exact-scope security gate.
- Do not let `live_resolved_ports()` report `PortSpec.host_ip` in place of the
  inspected binding. Declaration and observation are separate facts even when
  the CLI only needs the numeric endpoint.
- Do not change BIND to container loopback, drop either transport, split TCP and
  UDP across different host ports, or infer one protocol from the other.
- Do not add `0.0.0.0` as a fallback for Docker Desktop, IPv6, remote Docker,
  failed endpoint discovery, or a port collision.
- Do not broaden this issue to reverse SSH, victim targets, other management
  services, DNS hardening, firewall management, or Docker socket authority.
- Do not update `CHANGELOG.md` or the project version; release-please owns both.

## Non-Goals And Implementation Boundary

This issue does not redesign RAES or env-packs, add an APTL scenario schema,
change DNS zones, recursion, forwarding, telemetry, persistence, authentication,
TLS, or container-network reachability. It does not introduce a general remote
access mode, SSH tunnel manager, firewall controller, IPv6 publication, dynamic
host-port discovery protocol, or a new deployment backend.

The implementation boundary is the default DNS host-exposure fact in both
applicable authorities, reuse of the established declaration-to-Docker and
Docker-to-observation chains, truthful local documentation/reporting, exact
TCP/UDP evidence, bundled-asset digest consistency, and the mandatory clean-lab
workflow verification.
