# Libvirt Service Reachability Preflight

This note is the architecture preflight for APTL issue #759. It records the
cross-repository boundary and guardrails; it is not an implementation plan.

## Ownership And Decision

`aces_backend_libvirt` is not APTL source. It is shipped by the `aces-sdl`
distribution that APTL consumes through `pyproject.toml` and `uv.lock`. The
authoritative implementation, contracts, realization envelopes, and backend
tests therefore belong in the ACES repository. APTL must consume a released
fix; it must not patch `.venv`, copy the backend in-tree, or add a second
libvirt adapter.

Keep two existing ACES concerns distinct:

- `Node.services` is authored transport-service identity/listener intent.
- infrastructure ACLs are network reachability policy.

The libvirt realization-envelope artifacts already provide the canonical
mode-specific seam: the generic envelope discloses the `service` concern as
unsupported and the `acl` concern as realized through `libvirt-nwfilter`; the
guest-certified appliance envelope may realize and observe a bounded guest
service while disclosing ACLs separately. The backend must enforce those
dispositions. A declared service must not silently create an allow rule, weaken
an authored deny, or be reported as realized merely because it was copied into
`DomainSpec` or used by a readiness probe.

Consequently, nwfilter policy remains derived only from the existing ACL
translation path. A scenario that needs a reachable service needs two truthful
claims: a backend mode that realizes the service concern and explicit network
policy that permits the intended path. A listener descriptor, a successful TCP
probe, and firewall authorization are not interchangeable evidence.

## Required Existing Boundaries

- **SDL shape and semantics:** `aces_sdl.nodes.ServicePort`, `SDLModel`
  closed-world validation, `parse_int_or_var()`, semantic validation, scenario
  instantiation, and concrete revalidation remain the authoring authority. Do
  not create an APTL or libvirt copy of the service schema.
- **Compiler and plan contracts:** the ACES compiler, `RuntimeModel`,
  `ProvisioningPlan`, `PlannedResource`, planner diagnostics, and realization
  envelope membership remain the normal admission path. Because a public plan
  carries mapping payloads and can be constructed without the SDL parser, the
  libvirt interpreter must still defend its provider boundary.
- **Provider admission:** `interpret_provisioning_plan()` is the single pure
  validation/translation path used by both `LibvirtProvisioner.validate()` and
  `apply()`. Service entries that the selected mode cannot represent exactly
  must produce `aces_contracts.diagnostics.Diagnostic` errors before the
  driver is called. Missing protocol may use the SDL's TCP default; an explicit
  empty or unknown protocol must not be coerced. Boolean, fractional,
  non-integer, out-of-range, or missing ports and non-mapping entries must not
  be truncated or dropped. An optional SDL service name must either be
  preserved as optional or rejected as a disclosed mode constraint; it must
  not acquire a synthetic authored identity.
- **Network policy:** reuse `realize_node_acls()`, `NetworkAcl`,
  `_nwfilter_xml()`, and the existing libvirt driver filter lifecycle. Preserve
  fail-closed endpoint/CIDR resolution, ACL action/protocol/port validation,
  deterministic ordering, per-address UUID ownership, foreign-filter conflict
  refusal, convergence, interface `filterref` attachment, and owned cleanup.
  Service extraction must not add a parallel firewall rule type.
- **Errors and state:** use stable ACES diagnostic codes, resource addresses,
  severity, and bounded messages. Do not expose a raw service mapping or raw
  libvirt exception text, and do not add a service-specific exception
  hierarchy. An error must keep the prior `RuntimeSnapshot` unchanged through
  the existing `ApplyResult` failure path.
- **Observation:** `ServiceSpec`, guest observation, TechVault probes, and
  readiness checks may consume an already admitted declaration only for the
  claim they actually prove. TCP readiness does not prove UDP service state,
  ACL enforcement, source-range policy, or general reachability.
- **APTL adapter:** ADR-035 and ADR-046 remain binding. APTL-facing ACES errors
  continue through `aptl.backends.aces_diagnostics`, including redaction at the
  APTL envelope. APTL's Compose service/profile mapping and participant service
  bindings are a different backend concern and must not be reused as libvirt
  firewall policy.

## Security And Host-Layer Guardrails

- No new authentication, secret, environment, or durable configuration surface
  is needed. The existing libvirt connection URI and OS/libvirt authorization
  boundary remain authoritative; service fields must not become credentials or
  environment bindings.
- Service values must not be placed in process argv, shell commands, logs, or
  unredacted error envelopes. Libvirt XML receives only already-admitted typed
  values. Existing argv-list subprocess and redacted driver-diagnostic patterns
  remain unchanged.
- `nwfilter` is host-global policy and a filter is attached to every interface
  of the domain. An unscoped service-derived allow would therefore expose a
  port across attached segments and could override the scenario author's ACL
  intent. Do not generate one.
- Validation errors block all native side effects. Driver rollback, ownership
  checks, snapshot confirmation, and realization-envelope identity checks stay
  intact; service handling must not bypass them.
- No new persistence or telemetry store is justified. Runtime snapshots,
  operation status, realization/observation envelopes, and existing evidence
  redaction gates remain the only durable/reporting surfaces.

## Extensibility Seam

The extension point is the selected libvirt driver mode plus its published
realization envelope, not `_nwfilter_xml()` and not a hidden boolean in service
extraction. A future mode that intentionally derives ingress from declared
services would need an explicit envelope mechanism and a typed ingress-policy
parameter that preserves source networks/ranges, destination interface,
protocol, port or range, rule precedence, and default action. Until ACES owns
that policy shape, `acl-only` is the only honest nwfilter behavior.

## Gotchas And Anti-Patterns

- Do not treat “exposed by a node,” guest listener state, host publication,
  firewall authorization, probe success, and end-to-end reachability as one
  concept.
- Do not append service allows ahead of or behind ACLs and guess at precedence.
- Do not infer source CIDRs from whichever network happens to be first, apply
  an allow to every domain interface, or interpret omitted ACL endpoints as a
  service source-range policy.
- Do not silently drop malformed entries, unnamed-but-schema-valid entries, or
  unsupported protocols; do not coerce floats, booleans, or unknown protocols.
- Do not duplicate `ServicePort`, `Diagnostic`, `ApplyResult`, realization
  envelope, ACL DTOs, XML rendering, redaction, or snapshot logic.
- Do not use the health-probe consumer as evidence that service realization or
  network-policy enforcement exists.
- Do not validate only the normal SDL path. Directly constructed plan payloads
  remain an untrusted provider-boundary input and need the same fail-closed
  result before native mutation.
- Do not rely on the current local virtual environment when selecting the ACES
  baseline. `uv.lock` is the APTL dependency authority; the environment may be
  stale or VCS-installed.

## Non-Goals

- Realizing `Node.services` as automatic ingress policy.
- Redesigning ACES `ServicePort`, infrastructure ACL semantics, libvirt
  ownership/convergence, readiness probes, or realization envelopes.
- Changing APTL's Docker Compose networking, published ports, service/profile
  selection, participant binding, web/API authentication, secrets, or run
  archive formats.
- Claiming that an ACL starts a guest daemon, that a declared service opens a
  firewall, or that a TCP probe proves general service/network realization.
- Resolving APTL's separate `supports_acls=True` manifest claim; the in-tree
  Compose realization path does not currently show an ACL realization owner,
  so that claim needs its own truth-up rather than being folded into a libvirt
  dependency change.
