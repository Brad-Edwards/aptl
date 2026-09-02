# Issue #918 Authored OS Constraint And Substrate Boundary

This note fixes the architecture boundary for authored operating-system intent
before substrate-selection work begins. It is design guidance, not an
implementation plan. No new ADR is needed: ADR-046 already makes the admitted
RAES execution plan authoritative, ADR-048 owns generic materialization, and
ADR-051 owns artifact routes and backend realization evidence.

## Blocker and authority

OpenRAE/rae#1077 is a hard blocker. APTL must consume the portable RAES model,
processor admission, and disclosure authority delivered there. Until that
authority distinguishes binding constraints from author-granted backend
freedom, APTL must not parse, normalize, pattern-match, or assign local meaning
to `Node.os_version`.

In particular, APTL must not assume `os_version` is an image tag, distribution,
release, selector, compatibility range, or materialization recipe. Presence and
absence alone are also insufficient: an omitted fact and an explicitly open
fact may grant different freedom once interpreted by the portable authority.
APTL consumes that interpretation; it does not derive one from an empty string.

## Current policy and historical compatibility assumptions

The generic materializer was introduced in July 2026 by ADR-048 and commit
`421a836d`. Its deliberately small compatibility map supports Linux containers
and chooses:

- Debian or RHEL package family from declared package managers, defaulting to
  Debian when no `dnf`/`yum` package is present; and
- a minimal base or APTL's systemd-capable base according to whether service
  units are declared.

`base_image_for_os()` has accepted `os_version` since the first selector commit,
but has always ignored it "for forward compatibility." The operational key is
only `(OS family, package family, service-unit need)`. Later route-3 work reused
that selector for artifact availability, immutable local lookup, and
realization. `substrate_policy_variant()` truthfully reflects the current key,
not the unused version argument.

That history preserved scenario-independent materialization and avoided
product/node branches, but it did not establish compatibility semantics for an
authored distribution or version. ADR-048's wording that `os` and `os_version`
choose the base describes the intended input boundary, not evidence that the
current selector satisfies both values. Existing empty-string tests likewise
exercise legacy DTO plumbing; they do not grant open realization freedom.

## Architecture decisions and guardrails

1. **Portable demand first.** RAES owns the normalized OS realization
   requirement, including whether distribution/version facts are exact,
   constrained, explicitly open, or omitted. APTL's manifest advertises only
   support it can select and independently observe. It does not add an
   `os-version` concern name, constraint grammar, alias table, DTO, or
   diagnostic vocabulary.
2. **Backend capability second.** APTL may select among admitted substrates only
   inside the freedom RAES grants. Package-manager compatibility,
   service-manager need, target architecture/platform, artifact route, and
   local availability filter candidates; none may weaken or reinterpret the
   authored OS requirement. An incompatible intersection is unsupported, not a
   cue to substitute.
3. **One decision shared by admission and apply.** Plan-time admission,
   availability, immutable identity resolution, base-container creation, and
   post-start disclosure must consume the same typed substrate decision. Do not
   re-run a raw-field map at each stage or let a mutable tag decide again at
   apply time.
4. **Admission precedes mutation.** Portable OS capability admission must run
   before artifact materialization or any build, pull, tag, generated file,
   container, network, or volume change. This matters because the current
   `_plan_scenario()` gathers artifact availability before `RuntimeManager.plan()`
   and constrained component availability can build an image. The #1077
   integration must provide a side-effect-free processor gate or equivalent
   staged authority before that boundary; a late exception from
   `base_image_for_os()` is insufficient.
5. **Author intent and backend evidence remain separate.** The authored portable
   requirement stays plan demand. Selected distribution, selected version,
   target platform/architecture, immutable substrate identity, and realization
   mechanism are backend-observed evidence. Never copy the authored values into
   an observation or overload `ArtifactIdentity.version` with an OS release.
6. **Readback remains fail closed.** OS family, distribution, and version are
   disclosed only from the target actually selected and then from the running,
   project-owned resource at the strength required by the upstream contract.
   Missing, ambiguous, malformed, unavailable, or contradictory evidence
   produces no satisfaction and no successful lab result.

## Interaction of the selection inputs

| Input | Authority and permitted effect |
| --- | --- |
| `os` and `os_version` | RAES-authored portable demand. APTL consumes the #1077 normalized requirement and must not interpret the raw pair locally. |
| Package manager | `RuntimeConfiguration.packages[*].manager` is an operational compatibility requirement. `package_family()` may filter a candidate set. Its Debian default is permissible only inside admitted backend freedom; it cannot override a binding OS constraint. |
| Service units | `runtime.service_manager_units` requires a compatible service manager and continues to select the existing init mechanics. It filters OS candidates; it does not authorize a distribution substitution. |
| `Source` / artifact route | Exact artifact, materialization specification, and open dynamic composition remain the ADR-051 routes selected through RAES. `Source.name`, `Source.version`, image tags, aliases, and build directories are not OS-version semantics. Every selected artifact must still satisfy the portable OS requirement. |
| Target architecture | Current node substrate policy does not carry an authored architecture and Docker chooses the target platform implicitly. The selector seam must accept the portable target-platform requirement/capability from #1077; it must not assume the controller architecture or silently accept Docker's default platform. |
| Availability | Exact artifacts use the existing address-scoped artifact availability contract; route 3 uses strict target-daemon local lookup and its config-id digest domain. Availability proves obtainability, not OS compatibility or author intent. |
| Immutable identity | `SubstrateIdentity`, the verified config digest, canonical artifact mechanism, acquisition, timing, and provenance remain the identity evidence. Distribution/version observation is an additional portable realization fact, not a replacement digest or policy-variant string. |

An exact or constrained OS requirement applies to all three source routes, not
only generic dynamic composition. A digest-pinned vendor image can still be the
wrong OS; a materialization specification can still produce an incompatible
image. Conversely, open or omitted OS details do not automatically select route
3: the authored artifact posture still chooses the source route independently.

## Repository inventory of `os_version`

The inventory below records current intent without assigning portable semantics
that belong to #1077.

| File / values | Recorded intent |
| --- | --- |
| `examples/hospital-ransomware-surgery-day.sdl.yaml`: `ad01` = `Server 2022`, `exchange01` = `Server 2019`, `vendor-jump` = `11` | The example authors named specific Windows server/client releases independently of `source`. These are authored release constraints, not APTL image tags. APTL currently supports only Linux and must reject these before deployment rather than substitute Linux. |
| `examples/port-authority-surge-response.sdl.yaml`: `yard-hmi` = `10`, `gate-kiosk` = `11` | The example authors named specific Windows client releases independently of `source`. These are authored release constraints, not substrate recipes. |
| `tests/test_raes_node_desired_state.py`: `debian12` | A lowering/plumbing test proves the raw field is preserved into APTL's typed realization. It does not test or define Debian/version syntax. |
| `tests/test_raes_dynamic_composition.py`: Linux `12` | Substrate availability tests currently prove immutable target-daemon identity and missing/unsupported-family behavior. The value is deliberately semantically unasserted today and must be replaced or reclassified when portable constraint tests land. |
| `tests/test_raes_base_substrate.py`, `test_raes_materializer.py`, `test_raes_materializer_engine.py`, `test_materializer_integration.py`, `test_mixed_realization_integration.py`, `test_realization_declaration_gate.py`, and `test_realization_routing.py`: empty string | Direct DTO/planner fixtures use the legacy empty sentinel to exercise package, service, capability, mount, routing, and read-after-write behavior. Empty here means "this fixture supplies no version value"; it is not evidence of explicitly open author intent. |
| `tests/test_node_materialization_integration.py`: forwards `node.os_version`, whose fixture default is empty | Real-Docker coverage checks materialization and immutable route-3 startup, not OS-version semantics. |
| `tests/test_appliance_release_manifest.py`: Ubuntu `24.04` | Separate sealed-appliance release metadata: an exact guest fact bound to a golden image digest and architecture. It is not RAES node authoring and must not be reused as the scenario substrate schema. |

No file under `scenarios/` currently contains `os_version`. The five authored
scenario occurrences are examples, not catalog scenarios. Source-code
occurrences only transport the value through RAES lowering, deployment DTOs,
substrate resolution, and realization details; the separate appliance Pydantic
model is outside this path.

## Canonical incumbents to reuse

- **Portable schema and admission:** `parse_sdl_file()`, RAES node models,
  `compile_runtime_model()`, `RuntimeManager.plan()`, the #1077 realization
  requirement/capability authority, `create_aptl_manifest()`, RAES `Diagnostic`,
  and the SEM-218 `realization_disclosure()` gate.
- **Artifact route and availability:**
  `raes_artifact_mechanisms.select_route_over_mechanisms()`,
  `artifact_availability_for_scenario()`, address-scoped
  `ArtifactRequirementAvailability`, and the existing exact, materialized, and
  dynamic-composition profiles. Do not infer the route from OS fields.
- **Substrate policy and realization:** `base_container_spec()`,
  `base_image_for_os()`, `package_family()`, `resolve_substrate()`,
  `SubstrateIdentity`, `DeploymentBackend`, `ensure_generic_base_image()`, and
  `start_base_container()`. Evolve the single decision seam rather than adding a
  second OS selector.
- **Typed transport:** RAES `RuntimeConfiguration`, `NodeRealization`,
  `DeploymentNodeRealization`, `DeploymentRealizationSpec`, and the admitted
  execution-plan identity. Do not add a parallel node/source/substrate DTO.
- **Observation and evidence:** `observe_realization()`,
  `observe_runtime_concerns()`, `RuntimeSnapshot`, artifact satisfaction,
  `snapshot_after_apply()`, and RAES's provenance ledger. Extend the upstream
  concern/disclosure path; do not place realization evidence in authored
  `details()` or a log-only record.
- **Failures and observability:** RAES `diagnostic()`,
  `render_raes_diagnostics()`, `ApplyResult`, `LabResult`,
  `UnsupportedOsFamilyError` for the existing backend-policy miss,
  `BackendSeedError`, `BackendTimeoutError`, `get_logger()`, and `redact()`.
  Portable incompatibility should use upstream diagnostics, not a new APTL
  exception hierarchy.

## Cross-cutting security and validation passage

| Layer | Required behavior |
| --- | --- |
| API and CLI ingress | No new public selector is added. Web start remains behind `BFFMiddleware` Host/origin/CSRF/session checks and `api.deps.verify_token`; the local CLI remains the other ingress. Authored SDL cannot select a daemon, backend, registry credential, command, or host path. |
| Strict config and bundle shapes | Preserve `AptlConfig` and nested `extra="forbid"` models, `ScenarioSourceConfig` containment, `ScenarioBundle`, and the mandatory `bundle.root` / `scenario_root` flow. Do not add an environment-driven OS alias table, mapping file, or fallback root. |
| RAES parser/compiler/processor | Shape validation, normalization, exact/constrained/open/omitted classification, manifest capability matching, and blocking diagnostics belong to RAES/#1077. APTL consumes typed output and fails if the installed RAES version lacks the required authority. |
| Pre-mutation gate | OS admission must complete before component builds, generic-image preparation, pulls, tags, generated files, Docker create/run, networks, volumes, or content. Availability probes remain bounded and non-authoritative; no cache hit grants compatibility. |
| Artifact and substrate policy | Preserve digest/provenance verification, route profiles, strict route-3 local lookup, immutable start, `--pull=never`, capability allow-list, named-volume scoping, loopback publication default, and project labels. OS support does not broaden privilege, mounts, namespaces, devices, seccomp, registry access, or network exposure. |
| Target-daemon observation | Local and SSH backends probe the selected daemon through typed `DeploymentBackend` operations. Never inspect the controller's local cache for an SSH target. Distribution/version/platform readback must be bounded, normalized by the portable contract, and corroborated against the immutable selected artifact and running project-owned container. |
| Secret and environment boundary | OS selection requires no secret. Existing `.env` loading and owner-only `--env-file` binding remain unchanged. Environment values, registry credentials, tokens, keys, and raw inspect/exec output do not enter selection, evidence, diagnostics, logs, snapshots, or run records. |
| OS/process exposure | Fixed commands and non-secret addresses, image references, digests, distribution identifiers, and versions may be argv operands only where necessary. Preserve list argv, bounded timeouts, and the shared local/SSH runner; no shell interpolation. Never put credentials or rendered environment on argv. |
| Error envelope and logging | Unsupported, incompatible, unavailable, ambiguous, and readback-mismatch outcomes become address-scoped portable diagnostics and an unsuccessful `LabResult`. Use `redact()` and stable reason codes; do not expose raw Docker stderr, full commands, host paths, environment maps, registry responses, or image metadata. |
| Persistence and evidence | Use `RuntimeSnapshot`, artifact satisfaction, and the RAES realization-provenance ledger. Persist the portable observed distribution/version/platform plus immutable identity/mechanism only where the upstream schema permits. Do not create a substrate repository/cache table or persist mutable tags, host paths, source values, or backend singleton state. |

## Extensibility seam

The one selector seam must be parameterized by portable demand and target
capability, not by the raw SDL string:

`(portable OS requirement, package compatibility, service-manager need,
artifact route, target platform capability) -> admitted substrate candidate ->
immutable target-daemon identity -> observed portable realization evidence`

The next distribution/release, service manager, architecture, remote backend,
or substrate mechanism changes candidate data or backend probing at this seam.
It must not require changes to scenario-specific branches, RAES schema copies,
artifact-satisfaction logic, API/config shapes, or evidence persistence.

## Test guardrails

Acceptance coverage must drive real RAES parse/compile/plan/apply gates, not only
call `base_image_for_os()` with strings. Cover exact, constrained, explicitly
open, omitted, incompatible, and unavailable requirements; each case must assert
the selected artifact route, distribution/version/platform evidence, immutable
identity/mechanism, and whether mutation occurred. Negative cases must prove the
backend mutation boundary was never crossed. Include package-family,
service-unit, source-route, target-platform, local/SSH-daemon, mutable-tag, and
post-start readback mismatches. Preserve the existing exact artifact,
dynamic-composition, runtime concern, redaction, and real-Docker tests.

## Gotchas and anti-patterns

- Do not key a map directly on raw `os_version` or add regex/range parsing in
  APTL.
- Do not treat empty, missing, and explicitly open as synonyms.
- Do not treat a package-manager family, service manager, source name/version,
  image tag, Docker platform, or cached image as author-granted OS freedom.
- Do not make this a route-3-only check; exact and materialized artifacts can
  contradict the authored OS requirement too.
- Do not echo authored distribution/version into observed evidence or infer it
  solely from the chosen policy variant/tag.
- Do not overload `ArtifactIdentity.version`, `Source.version`, or
  `substrate_policy_variant()` with OS realization evidence.
- Do not check only after a build, pull, generated-file write, or container
  start. Unsupported constraints fail before all mutation.
- Do not duplicate selection in availability, materialization, and observation;
  thread one typed, address-scoped decision.
- Do not broaden `supported_os_families`, realization support, or observation
  strength before both selection and independent readback are implemented.
- Do not catch broad exceptions and convert malformed portable demand into open
  backend freedom.

## Non-goals and implementation boundaries

This issue does not define the portable meaning of `os_version`, design RAES
#1077, add an APTL constraint language, migrate the Docker backend to VMs, add
Windows container support, add a registry/catalog service, or reinterpret the
sealed appliance manifest. It does not change artifact-route semantics,
package-manager semantics, component source ownership, scenario roots, secret
binding, privileges, host exposure, lifecycle persistence, or Compose's role as
a backend wire format.

The implementation boundary is integration of the released #1077 authority
into APTL's existing manifest, admission, single substrate decision,
target-daemon availability, immutable start, and portable observation paths.
If the upstream authority cannot express or disclose a required fact, APTL
fails closed and remains blocked; it does not ship a local approximation.
