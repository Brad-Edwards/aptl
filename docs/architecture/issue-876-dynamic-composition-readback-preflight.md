# Issue 876: dynamic-composition readback boundary

`dynamic-composition` may be declared only when APTL can materialize and
independently verify the complete declared runtime shape. This note fixes the
boundary for that work; it does not add a second desired-state schema or a
second SEM-218 disclosure gate.

> **Update (2026-07-30).** The preflight below was written against raes 2.0.0,
> where the six runtime dimensions were not RAES-lowered concerns and the
> boundary anticipated a backend-owned attestation feeding artifact satisfaction.
> raes 3.1.0 (OpenRAE/rae#985) instead lowers those dimensions into the
> realization concern registry, so the delivered design is a plain observe-and-
> disclose: the "provider-owned runtime observation adapter" described here is
> `aptl.backends.raes_runtime_observation`, and it discloses each observed concern
> at RAES's own payload path through RAES's registry projector (its
> secret-boundary value commitment replaces any APTL-local redaction). RAES's
> `realization_disclosure` owns the fail-closed comparison. Every security and
> secret-boundary guardrail below still holds. The route-3 source-artifact
> satisfaction (originally split to #892) is implemented in the same change; see
> `issue-892-dynamic-composition-artifact-preflight.md` and ADR-051.

## Decision

The existing RAES `RuntimeConfiguration` remains the desired-state owner and
`AptlRealization` / `DeploymentRealizationSpec` remain the only APTL lowering
records. The artifact mechanism is disclosed through RAES's existing
`ArtifactSatisfactionDisclosureModel` in the returned `RuntimeSnapshot`; it is
not represented as a local capability flag, a Compose fragment, or a new
snapshot schema.

The existing concern readback path remains unchanged:

- `CONCERN_PAYLOAD_PATH`, `observe_realization()`, `snapshot_after_apply()`,
  and `RuntimeManager.apply()` own node type, OS family, domain topology,
  networks, content, generated artifacts, and persistent volumes.
- `raes_materializer_engine.materialize_node()` owns per-operation
  read-after-write for package, identity, filesystem, dependency-manifest, and
  service-unit materialization.
- A provider-owned runtime observation adapter must attest the remaining
  `RuntimeConfiguration` dimensions: environment, published ports, Linux
  capabilities, mounts, readiness probes, and forwarding agents. It returns
  a secret-free observation or no attestation. It must use only typed
  `DeploymentBackend` operations (`container_inspect`, `container_exec`, and
  project-scoped listing/probes), never raw Docker/Compose calls in the RAES
  adapter.

The adapter compares normalized observed values to the compiled runtime input,
including multiplicity and read-only/access semantics. Any missing,
malformed, ambiguous, timed-out, cross-project, or mismatched dimension makes
the node's dynamic-composition satisfaction absent. A running container, a
successful `docker run`, an image config, a planned runtime field, or a
materializer success result is not evidence of these dimensions.

`raes_manifest.py` may add the `dynamic-composition` artifact mechanism only
with its exact profile identity, supported requirement kinds, and the exact
acquisition/timing routes APTL actually performs. For generic local substrates,
that route is expected to be `local-lookup`/`realization` only if the resulting
artifact identity and all satisfaction references can be independently
attested. Do not claim `pull`, `copy`, `import`, `publication`, or
`backend-preparation` merely because a Docker image or checked-in source was
used somewhere in lowering. The returned satisfaction must pass RAES's existing
availability, route, trust-reference, and realization checks; no local
approximation of those checks is allowed.

## Security and evidence boundary

Environment and forwarding readback must compare names, provenance,
classification, and a non-reversible value commitment where a value is needed;
they must never emit secret, redacted, or operator-secret values. Inspect output,
probe stdout/stderr, environment maps, tokens, enrollment identities, rendered
configuration, host paths, and command lines remain outside snapshots,
`ApplyResult.details`, diagnostics, logs, telemetry, and run records.

Published-port readback must prove host IP, host port, container port, and
protocol, preserving the existing loopback default and host-port conflict
policy. Mount readback must prove type, project-scoped source, destination, and
read-only state, while continuing to reject Docker socket/control-interface,
host-device/namespace, privileged, unconfined-seccomp, and unauthorized
capability exposure through the existing substrate/policy validation. Readiness
is a provider probe result, not Docker health alone; forwarding requires an
agent-specific live/configuration probe that exposes no credential material.

Use `diagnostic()` / `render_raes_diagnostics()` and the existing redaction
boundary for failures. Do not introduce a runtime-observation exception family
or return raw backend failures. A failed attestation must turn the node's
artifact satisfaction into an ordinary fail-closed RAES realization failure.

## Boundaries and extensibility

The seam is one provider-owned, typed runtime observation result parameterized
by `(node address, compiled RuntimeConfiguration, typed realization binding)`.
Adding the next runtime dimension extends that result and its backend probe;
it does not add a new manifest mechanism, snapshot DTO, or scenario-specific
branch. Keep the artifact profile and route declarations in the canonical
manifest, and let RAES own artifact availability/context and satisfaction
validation.

Non-goals: changing the RAES concern registry, declaring an appliance image as
dynamic composition, treating legacy Compose as desired state, exposing secret
values or raw inspections as evidence, supporting unmaterialized runtime
families, or broadening host privilege/network exposure. The implementation
must fail before reporting the node realized whenever any declared runtime
dimension lacks independent readback.
