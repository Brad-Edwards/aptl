# Issue #892 Dynamic-Composition Artifact Satisfaction Preflight

This note fixes the repository-wide boundary for ADR-051 route 3. It is design
guidance, not an implementation plan. The issue completes the source-artifact
half of a mechanism whose runtime-concern half is already owned by RAES 3.1.0
and APTL's readback adapter.

## Architecture decisions

RAES remains the contract and gate owner. Keep using
`ArtifactRequirement`, `ArtifactAvailabilityContext`,
`ArtifactSatisfactionDisclosureModel`, `RuntimeSnapshot`,
`realization_disclosure()`, and the realization-provenance ledger. Do not add
an APTL artifact DTO, another availability schema, a second runtime gate, or a
boolean such as `is_dynamic_composition`.

Route selection remains the intersection implemented by
`raes_artifact_satisfaction.select_route()`. Branch satisfaction on the full
selected mechanism profile, acquisition, and timing tuple. Do not equate
`exact_artifact is None` with materialization: both constrained
materialization and open dynamic composition have no exact artifact.

The generic-substrate decision remains
`raes_base_substrate.base_container_spec()` /
`raes_materializer.base_image_for_os()`, derived from the typed node OS,
package family, and service-manager need. `Source.name`, `Source.version`,
scenario or node names, Compose services, and cache contents never select the
substrate. The source-image resolver must recognize an admitted
dynamic-composition route as intentionally image-free before its current
unmapped-service and untrusted-image failures. Returning no component image is
valid for this one selected route; an unresolved exact or materialization route
remains an error.

Resolve the substrate through a typed `DeploymentBackend` local-image operation
against the target daemon. Resolution returns a truthful digest/media-type pair
and an immutable local start reference for that same identity. Availability
records the digest under the compiled node address in
`verified_integrity_refs` and records
`dynamic_composition_provenance_ref()` in `verified_provenance_refs`. Both are
required by RAES's `_trust_claims_verified()` gate. Do not fabricate empty-set
success, copy facts between addresses, or use `available_artifact_digests` as a
substitute for verified integrity.

The realized disclosure has the shape fixed in ADR-051: a provider-neutral
generic-substrate `ArtifactIdentity`, the canonical dynamic-composition
profile, `local-lookup` / `realization`, the observed digest as its sole
integrity reference, and the canonical mechanism provenance reference. It has
no candidate, materialization specification, locked input, constraint, registry
location, repository, account, region, channel, bundle path, or host path.

Availability lookup and container readback must return the same kind of digest.
Do not compare a registry manifest digest on one side with Docker's image/config
ID on the other, and do not label a config ID as an OCI manifest. If a target
daemon cannot provide one unambiguous immutable identity and truthful media
type for the selected local substrate, the route is unresolved.

`local-lookup` is a real acquisition boundary. Once availability has selected
the substrate, realization starts its verified immutable local reference, not
the mutable selector used to find it, and must not let `docker run` silently
pull a missing or retagged image. Reuse the generic-base preparation/start
boundary and fixed argv runner, with local-only semantics for the selected
route. An unavailable or changed substrate produces no container and no ready
snapshot. RAES's independently observed digest remains a defense-in-depth gate
against a backend mismatch.

Issue #891's root separation is binding. The `ScenarioBundle` is resolved once
and `bundle.root` remains the root for scenario inputs. `project_dir` remains
the operator `.env`, backend transport, and run-storage boundary. Substrate
policy is code-owned backend capability, not a bundle asset or a new root.
Neither root is artifact identity, and neither is cached as mutable
request-global backend state.

## Canonical incumbents

- Artifact contracts and gates: RAES
  `ArtifactRequirement`, `ArtifactRequirementAvailability`,
  `ArtifactSatisfactionDisclosureModel`,
  `artifact_requirement_diagnostics()`,
  `evaluate_artifact_realization()`, and `realization_disclosure()`.
- Mechanism identity and route declaration:
  `raes_artifact_mechanisms.dynamic_composition_profile()`,
  `dynamic_composition_provenance_ref()`,
  `aptl_artifact_mechanisms()`, and `raes_manifest._REALIZATION_SUPPORT`.
- Availability and route selection:
  `artifact_availability_for_scenario()`, its single
  `compile_runtime_model()` pass and address partitioning, plus
  `select_route()`. Do not parse node names back out of addresses or recompile
  per requirement.
- Substrate policy and effects:
  `base_container_spec()`, `base_image_for_os()`,
  `package_family()`, `ensure_generic_base_image()`,
  `start_base_container()`, `DeploymentBackend`, and the local/SSH backend's
  shared typed runner. Policy selects; the backend resolves and observes.
- Image-free routing and realization:
  `resolve_node_image()`, `_is_materializable_node()`,
  `_image_free_node_addresses()`, `_realize_node_subset()`,
  `realize_nodes()`, and `raes_materializer_engine.materialize_node()`.
- Observation and disclosure:
  `observe_realization()`, `observe_runtime_concerns()`,
  `snapshot_after_apply()`, `satisfactions_for_plan()`, and
  `AptlProvisioner._with_artifact_satisfactions()`.
- Failures and observability:
  RAES `Diagnostic`, `diagnostic()`, `render_raes_diagnostics()`,
  `ApplyResult`, `LabResult`, `BackendSeedError`, `BackendTimeoutError`,
  `UnsupportedOsFamilyError`, `UnauthorizedCapabilityError`, `get_logger()`,
  and `redact()`. Do not add an artifact-lookup exception hierarchy.

## Security and validation passage

| Layer | Required behavior |
| --- | --- |
| API and control-plane authentication | No endpoint or selector is added. API lab start remains behind `BFFMiddleware` Host/CSRF/session checks and `verify_token`; local CLI startup remains the other ingress. SDL cannot choose a backend, daemon, registry credential, root, or command. |
| Strict configuration and bundle shapes | `AptlConfig` and nested models retain `extra="forbid"`; `ScenarioSourceConfig.root`, `ScenarioBundle`, and #891's mandatory `scenario_root` flow remain authoritative. No environment variable or optional fallback root is introduced. |
| RAES parser/compiler/planner | The authored source passes RAES Pydantic shape validation, compilation, open-realization support checks, manifest route checks, and address-scoped artifact diagnostics. APTL does not duplicate these schemas or explicitness rules. |
| Base-substrate security policy | Reuse the fixed OS/package/service selector, capability allow-list, loopback publication default, named-volume scoping, and unsupported-OS failure. Dynamic composition does not broaden capabilities, mounts, seccomp, namespaces, host devices, Docker socket access, or host publication. |
| Target-daemon image lookup | Lookup runs through the selected deployment backend and its bounded argv runner. The SSH backend must inspect its remote daemon through `DOCKER_HOST`, not the controller's local cache. No shell, ambient registry fallback, or raw daemon error crosses the adapter. |
| Secret and environment binding | Substrate resolution needs no secret. Operator values still flow from `project_dir/.env` through `load_dotenv()` and the owner-only `--env-file` path; values never enter image lookup argv, satisfaction, snapshots, logs, or diagnostics. Authored fixture values continue through RAES's concern projector and commitments. |
| OS/process exposure | Non-secret image references, digests, container names, and fixed flags may be argv operands. Tokens, passwords, private keys, registry credentials, rendered environment, and raw inspect output may not. Preserve bounded timeouts and `shell=False` list argv. |
| Runtime readback and trust gate | The running, project-labelled container must be observed; every declared runtime concern must pass RAES's projector/readback gate; the source-artifact digest must be observed independently and belong to the verified integrity set. Any omission or mismatch returns the baseline snapshot. |
| Error envelope and logging | Missing/malformed substrate state becomes an address-scoped redacted RAES/provisioner failure and ultimately an unsuccessful `LabResult`. Do not include raw Docker stderr, full commands, image metadata, host paths, environment maps, or source values in the operator envelope. |
| Persistence/evidence | Use the existing `RuntimeSnapshot` artifact satisfaction and RAES provenance ledger. Existing run-store redaction applies. Persist digest/profile identities only; do not add a repository, cache record, registry location, bundle root, or generated secret-bearing file. |

## Extensibility seam

The next reasonable variation is a second OS/version, service-manager substrate,
or target architecture. The seam belongs between the existing typed
base-substrate selector and a target-daemon local-image resolver:

`(OS, OS version, package family, service-manager need, target platform) ->
selected generic policy variant -> immutable local image identity and start
reference`

Adding a variant changes that policy/resolver, not artifact satisfaction, RAES
schemas, source-image routing, or scenario-specific code. Multi-platform
resolution must identify the image actually used by the target daemon rather
than assuming a registry index digest equals a platform manifest or local image
ID.

## Gotchas and anti-patterns

- Do not route on explicitness alone or on `exact_artifact is None`.
- Do not let the existing non-exact materialization branch consume the open
  dynamic route.
- Do not require a Compose service mapping for a route intentionally owned by
  the generic materializer.
- Do not choose the substrate from `Source`, aliases, profile hints, scenario
  names, or a cache hit.
- Do not repeat route/profile matching in availability, realization, and
  disclosure with slightly different tuple logic; reuse `select_route()`.
- Do not report only `verified_integrity_refs`; the disclosed provenance must
  also be in `verified_provenance_refs`.
- Do not disclose a planned digest, mutable tag, first arbitrary `RepoDigest`,
  or registry location as observed identity.
- Do not start the mutable tag after verifying a digest; bind the base-container
  operation to the verified immutable local start reference.
- Do not let Docker auto-pull on a declared local-lookup route.
- Do not treat the substrate digest as proof of packages, configuration,
  identity, ports, mounts, capabilities, forwarding, or listeners.
- Do not catch broad exceptions and turn malformed authored requirements into
  availability. Malformed input stays a parser/compiler failure.
- Do not store the resolved substrate on a reusable backend singleton or in run
  persistence; availability facts are plan/address scoped.
- Do not test only payload shape. Exercise RAES's real admission and runtime
  gates, and assert a mismatch returns the baseline snapshot with no ready node.

## Non-goals and boundaries

This issue does not add another artifact mechanism, change the dynamic profile
or route, redesign RAES, make arbitrary images valid substrates, add registry
authentication, broaden runtime capabilities or network exposure, implement
forwarding agents, make bind/tmpfs concerns materializable, redesign
image-free placement, or change API/CLI authentication.

It does not migrate every existing generic node to an authored open source
route, change the default TechVault scenario or catalog, redesign evidence
storage, add pack acquisition, or remove Compose compatibility. A route-3
scenario fixture is acceptance evidence, not a new public scenario unless a
separate product decision adds it to the catalog.
