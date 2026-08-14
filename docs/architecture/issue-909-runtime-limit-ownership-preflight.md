# Issue #909 Runtime-Limit Ownership Preflight

This note fixes the architecture boundary for removing APTL's universal
image-node `ulimits` fallback. It is guidance, not an implementation plan.
[ADR-046](../adrs/adr-046-dynamic-raes-scenario-realization.md) and
[ADR-051](../adrs/adr-051-component-level-raes-realization.md) remain binding.

## Current evidence and blocker

- `src/aptl/core/deployment/_compose_node_generation.py` currently adds
  unlimited `memlock` and `nofile=65536` to every generated image-backed
  service. This is backend-selected state, not admitted scenario state.
- The static `docker-compose.yml` is narrower: Wazuh manager declares unlimited
  `memlock` and `nofile=655360`; Wazuh indexer declares unlimited `memlock` and
  `nofile=65536`. The official Wazuh single-node Compose model carries those
  same component-specific values. Official OpenSearch Docker guidance requires
  unlimited `memlock` when memory locking is enabled and at least 65536 open
  files. This is requirement evidence, not authorization to inject those values
  into unrelated nodes.
- The pinned TechVault env-pack (`raes-env-packs==3.9.0`) currently declares no
  node `resources` and no `runtime.operational_policy.resource_limits`, including
  on `wazuh-manager`, `wazuh-indexer`, and `shuffle-opensearch`.
- Pinned `raes==3.3.0` exposes strict
  `RuntimeOperationalPolicy.resource_limits` fields for memory, memory swap,
  CPU, PIDs, and open files. It cannot express `memlock`, and resource limits
  have no entry in RAES's `CONCERN_PAYLOAD_PATH`; they therefore do not yet pass
  through the ordinary SEM-218 admission and declared-versus-observed gate.
  [OpenRAE/rae#1066](https://github.com/OpenRAE/rae/issues/1066) merged through
  PR #1080 on 2026-08-10, but no RAES release newer than 3.3.0 publishes that
  contract yet. APTL remains blocked on a released version it can pin and
  qualify; the merged upstream code is not a reason to copy the schema locally.
- `build_aptl_realization_envelope()` currently labels
  `resource-allocation` as daemon-observed using
  `compose-resource-limits-readback`, but `observe_realization()` publishes no
  corresponding resource-limit concern. That envelope label is not evidence
  of admission or observation and must not be used to justify the fallback.

The component candidates supported by repository and vendor evidence are shown
below. Final ownership is governed by
[OpenRAE/env-packs#288](https://github.com/OpenRAE/env-packs/issues/288), which
remains open and has not produced a released TechVault pack carrying these
requirements, not by this table.

| Component | Evidence to classify | Required owner decision |
| --- | --- | --- |
| Wazuh manager | The repository and official Wazuh Compose model use unlimited `memlock` and `nofile=655360`. | TechVault-authored exact/constrained requirement if component behavior requires it, or an explicit applicable apparatus boundary; never a name-based APTL default. |
| Wazuh indexer | Wazuh/OpenSearch models use unlimited `memlock` and `nofile=65536`. | Same classification, preserving whether the contract is an exact value, minimum, or admitted open choice. |
| Shuffle OpenSearch | It is an OpenSearch component; official OpenSearch guidance supplies the candidate limits, while the checked-in static service currently omits them. | TechVault must state the binding outcome or explicitly admit backend choice; product family detection in APTL is not authority. |
| Other scenario nodes | No component-specific non-default `ulimit` evidence was found in the repository. | Absence stays absence. APTL must not grant the OpenSearch/Wazuh set. |
| APTL control-plane/apparatus services | They are outside TechVault scenario ownership. | Any limits remain an explicit APTL apparatus/deployment contract and must not be copied into SDL as scenario intent. |

## Architecture decisions

- Keep one authority chain: TechVault/RAES authored posture -> RAES
  parser/compiler/planner -> typed APTL realization -> deployment backend ->
  independent observation -> RAES realization disclosure and provenance.
- Preserve three distinct states: no requirement, a binding exact/constrained
  requirement, and an explicitly open backend choice. `None`, `open`, and a
  concrete limit are not interchangeable. A backend selection on an open
  surface is recorded as backend-realized provenance; it is never rewritten as
  author-declared state.
- The upstream RAES model and concern registry own the portable schema,
  normalization, explicitness, and non-approximation comparison. APTL may add a
  typed lowering field to `NodeRealization` / `DeploymentNodeRealization` only
  as a faithful projection of the admitted RAES value. Do not create an APTL
  `Ulimit`, `ResourceLimit`, or TechVault component-policy schema.
- A backend-owned open choice is legal only when the resolved realization
  envelope expressly bounds that concern and APTL's manifest discloses the
  supported observation strength. The envelope's concern label alone is not a
  value boundary; the envelope expression/binding and resulting provenance are
  load-bearing.
- Unsupported kinds, ranges, values, or observation strengths fail in planning
  or provisioner validation before `DeploymentBackend.realize()` mutates the
  target. Compose schema validation is defense in depth after admission, not
  the admission decision.
- Compose is a renderer. It receives normalized admitted limits and maps only
  those limits to `ulimits` or backend resource fields. It does not infer them
  from image reference, node/service name, profile, environment, healthcheck,
  or product family.
- Readback reuses project-scoped `safe_inspect()` / `settled_inspect()` and
  Docker daemon state. Normalize `HostConfig.Ulimits` (and cgroup fields only
  when their distinct portable concern calls for them), reject duplicates or
  malformed entries, and disclose through RAES's projector. Missing,
  substituted, weaker, or excess limits omit/refuse the concern so RAES fails
  the apply. Do not echo the desired value.
- Service health and authenticated readiness remain required startup gates, but
  neither proves a resource limit. Conversely, matching limits do not prove
  component readiness.
- The static Compose path may retain its explicit component limits while it is
  supported. Removing the generated universal fallback must not silently erase
  an independently governed static component requirement.

## Concepts that must remain separate

- `Node.resources` (`ram`, `cpu`) is portable compute allocation intent. It is
  not a POSIX process `rlimit` and must not be blindly lowered to Compose
  `ulimits`.
- `runtime.operational_policy.resource_limits` is runtime policy intent, but its
  current RAES 3.3 shape is incomplete for this issue and is not concern-gated.
- Compose `deploy.resources`, `mem_limit`, and `ulimits` are backend syntax, not
  portable contract vocabulary.
- Host prerequisites such as `vm.max_map_count`, swap policy, daemon defaults,
  and physical capacity are apparatus/host admission concerns. They are not
  container limits and must not be smuggled into the scenario limit record.
- A vendor sample is requirement evidence. It is not authored TechVault state,
  an APTL capability declaration, or observed satisfaction.

## Canonical incumbents and cross-cutting passage

| Layer | Required reuse and guardrail |
| --- | --- |
| HTTP/control-plane ingress | No new route or selector is needed. API start remains behind `BFFMiddleware` Host/CSRF/two-factor session handling and `verify_token`; CLI start remains the other ingress. Limit data comes from the selected admitted scenario, not request fields. |
| Configuration and bundle shapes | Keep `AptlConfig` and nested `extra="forbid"` models, `ScenarioSourceConfig`, `ScenarioBundle`, env-pack staging, `validate_pack`, and exact content-manifest validation. Do not add a permissive config map or read limits from `.env`. |
| Contract validation | Reuse RAES `RuntimeOperationalPolicy`/successor resource-limit models, `RealizationDesignation`, compiled requirements, realization-envelope domains/bindings, manifest support diagnostics, and `realization_disclosure()`. Unsupported and excess cases belong to this one gate. |
| APTL lowering | Extend only `interpret_provisioning_plan()`, `NodeRealization`, `DeploymentNodeRealization`, and `DeploymentRealizationSpec` as a lossless projection after upstream admission exists. Preserve omitted/open/concrete state and provenance; do not reparse SDL YAML. |
| Rendering and backend capability | Reuse `_operational_config()`, `render_realization_compose()`, `_validate_realization_compose_model()`, and the single `DeploymentBackend` boundary. Local and SSH Compose must share normalization and the existing runner; no raw Docker subprocess in the RAES adapter. |
| Observation | Reuse `observe_realization()`, `observe_runtime_concerns()`, `_record()`, `_disclose()`, `safe_inspect()`/`settled_inspect()`, project labels, and `container_inspect()`. Observation errors fail closed as omissions. |
| Secrets and environment binding | Limits are non-secret. Operator secrets still flow only through the control-plane `.env`/`EnvVars` path and Compose's explicit `--env-file`; do not include environment maps or raw inspect output with limit evidence. |
| OS/process exposure | Keep list argv, `shell=False`, bounded timeouts, project-scoped container names, and the SSH backend's `DOCKER_HOST` runner. Portable values may enter a generated Compose file; no token, credential, rendered environment, host path, or raw command is added to argv/logs. |
| Errors and logging | Reuse RAES `Diagnostic`, `diagnostic()`, `render_raes_diagnostics()`, `ApplyResult`, `LabResult`, `BackendTimeoutError`, `get_logger()`, and `redact()`. Log stable codes, addresses, limit kinds, and outcome classes only; no raw Docker stderr/inspect body and no new exception hierarchy. |
| Persistence/evidence | Reuse `RuntimeSnapshot`, RAES realization provenance, `observation_evidence`, and existing run-store redaction. Persist normalized non-secret requirement/selection/observation identities only; do not add a limits repository, cache, sidecar JSON schema, or Compose artifact as scientific truth. |
| Verification | Extend the established runtime-observation/gate tests, Compose-rendering/effective-model tests, manifest-envelope tests, env-pack integration/static gates, and clean lab boot required by `.gc/plan-rules.md`. Exercise the real RAES parser/planner/disclosure path, not only helper payloads. |

The acceptance matrix is conjunctive: required and matching; absent and not
injected; open and bounded with backend-realized provenance; unsupported and
rejected before mutation; substituted/weaker and rejected by readback; and
excess/undeclared and rejected. Include hard/soft ordering, duplicate names,
numeric boundaries, unlimited sentinels, empty versus omitted, local/SSH parity,
timeout/malformed inspect, and project-ownership cases.

## Extensibility seam

The parameter is the admitted RAES resource-limit concern plus its resolved
posture/provenance, passed per node to a backend capability/normalization table:

`portable limit kind + admitted bound/posture -> backend field -> normalized observed value`

Adding the next limit kind or another backend extends that mapping and its
observer. It does not change TechVault component branches, introduce a second
schema/gate, or require editing a universal default. Backend-specific names may
appear only inside the backend mapping.

## Non-goals and anti-patterns

- Do not implement around OpenRAE/rae#1066 with an APTL-only field, governed
  extension, Compose fragment, image label, environment variable, or node-name
  allowlist.
- Do not treat OpenSearch detection, image metadata, a healthcheck, vendor docs,
  or a successful boot as authorization.
- Do not collapse absent, zero, unlimited, inherited/default, and open values.
- Do not use `setdefault`, a global Compose anchor, daemon default, or base-image
  mutation to preserve the universal fallback under another name.
- Do not claim daemon-observed resource allocation in the manifest/envelope
  until the actual admitted concern is read back and disclosed end to end.
- Do not let an open choice escape its resolved envelope, silently substitute a
  supported value, accept an undeclared extra limit, or downgrade observation
  strength.
- Do not redesign readiness, resource scheduling/campaign budgets (DEP-007),
  host prerequisite admission, image/source selection, API authentication,
  secret handling, persistence, or non-Compose providers in this issue.
