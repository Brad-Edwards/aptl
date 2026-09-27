# Issue #993 Boot Realization Regressions Preflight

This note fixes the boundary for extending the existing installed-wheel boot
gate. It is architecture guidance, not an implementation plan. Issue #969 still
owns the job, fixture identity, installed-artifact boundary, and cleanup proof.
Issue #1126 owns automatic coverage against every advertised realization
concern, and issue #1099 owns shared contract tests.

## Decision

Keep one product-neutral scenario in
`tests/fixtures/materialization-envelope.sdl.yaml` and one
`clean-install-lab-boot` job. Extend that scenario with one causal realization
chain:

- non-sensitive, inline content configures a package-owned service on the
  existing generic node;
- the existing generic materializer installs the package, places the content,
  then enables and starts the declared service-manager unit;
- the service listens on the authored container port, which is published on an
  explicit loopback host binding; and
- one end-only RAES `workflows` resource traverses the ordinary orchestrator
  adapter and produces a terminal portable result plus history.

The assertions must observe effects, not declarations. Read the exact content
inside the project-owned container, query the service manager for enabled and
active state, inspect the realized Docker port tuple, connect to the listener,
and parse the persisted workflow result with RAES's
`WorkflowExecutionState`. A successful CLI exit, a running container, generated
Compose, or the presence of an unparsed JSON file is not sufficient.

Use a package-owned SSH daemon as the small service shape: its configuration can
move the listener away from the package default, making content placement
causal to both listener and port assertions. Bind the host side to loopback and
use a high, fixture-owned port. Do not add a credential, interactive login, or
public bind merely to prove reachability.

`workflows` and `runtime.orchestration_authorities` are different concepts. The
former is the portable control-flow adapter selected here. The latter can grant
a workload host-root-equivalent Docker authority and carries image, endpoint,
operator-policy, and ownership obligations governed by ADR-055 and issues #949
and #974. It does not belong in this generic smoke. Its focused tests and
TechVault qualification remain the appropriate coverage.

## Canonical Incumbents

| Concern | Existing owner to reuse |
| --- | --- |
| Installed artifact and lifecycle | `.github/workflows/checks.yml`, `hatch_build.py`, `src/aptl/_asset_manifest.py`, `aptl.core.assets.materialize()`, and the public `aptl lab init/start/status/stop` commands |
| Scenario shape and admission | The shared `materialization-envelope.sdl.yaml`, RAES parsing/compilation/planning, `AptlProvisioner`, and `DeploymentRealizationSpec`; add no CI-only schema or hand-built deployment DTO |
| Content policy and execution | `raes_image_free_content_realization.py`, `raes_content_source_policy.py`, `raes_materializer.py`, `raes_materializer_engine.py`, and `DockerMaterializationExecutor`; retain content-before-service ordering and read-after-write |
| Service setup and observation | RAES `RuntimeConfiguration.service_manager_units`, `BaseContainerSpec`/`InitRequirements`, the packaged generic systemd build contexts, and `observe_service_manager_units()` |
| Listener and port realization | RAES service/runtime models, `PublishedPort`, `_append_base_ports()`, `raes_runtime_network_observation.py`, `_compose_port_readback.py`, and project-scoped Docker inspection |
| Workflow orchestration | RAES workflow models, `AptlOrchestrator`, `WorkflowEngine`, `WorkflowResultContract`, and `WorkflowExecutionState`; do not invent a smoke-workflow result DTO |
| Persistence | `LocalRunStore`, its path containment and redaction boundary, and the existing `runs/<run>/orchestration/<address>/` result/history layout |
| Identity and cleanup | Strict `AptlConfig`, `WorkspaceOwnership`, the Compose project label plus `aptl.node.address`, `observe_project_runtime()`, `project_scoped_volume_names()`, and `scripts/ci/assert_project_teardown.py` |
| Errors and observability | RAES `Diagnostic`, `LabResult`, startup diagnostics, `get_logger()`, and `redact()`; CI adds assertions, not a new exception, log, telemetry, or result hierarchy |

The shared fixture also feeds `tests/test_lab_fresh_start.py`,
`tests/test_imagefree_admission_integration.py`, `tests/test_scenarios.py`, and
`tests/test_platform_ci_gates.py`. Keep those consumers coherent. In
particular, consolidate or narrow the separate service-only live fixture in
`test_imagefree_admission_integration.py` once the owned fixture covers the same
service path; two live scenarios asserting the same behavior would add time
without adding a boundary.

## Security And Cross-Cutting Passage

| Layer | Required passage |
| --- | --- |
| GitHub and product auth | Retain read-only workflow permissions. The job uses the local CLI and Docker daemon, adds no API/MCP route, and does not weaken API token, Host, CSRF, session, or participant authorization gates. |
| Config and scenario validation | `aptl.json` continues through strict `AptlConfig` with `extra="forbid"`; the SDL continues through RAES parser, compiler, planner, realization-support diagnostics, and runtime materialization qualification. Do not add a CI-only config flag or duplicate Pydantic/RAES model. |
| Content and path policy | Keep the fixture content inline, bounded, and explicitly non-sensitive. Destination validation, project containment, forbidden-source policy, stdin delivery, atomic replacement, and digest readback remain authoritative. Never put content bodies or credentials in Docker argv, labels, logs, or workflow output. |
| Service and host privilege | Select service management only through `service_manager_units`; reuse the generic systemd substrate and its existing bounded init capabilities/mounts. Do not author `privileged`, host namespaces, devices, capabilities, Docker sockets, or extra host binds in the smoke. |
| Network exposure | RAES port shape checks, the loopback default/policy, Docker's port binding, daemon inspection, and listener observation must all agree on protocol, host IP, host port, and container port. A wildcard host binding is a failure. Use an argv-based bounded connection probe and no shell interpolation of scenario data. |
| Ownership and OS lookup | Resolve exactly one container by the durable workspace project identity and admitted node label before any `docker exec` or inspect. Never select by bare container name, broad prefix, image, or daemon-wide search. |
| Workflow shape and persistence | RAES validates the end-only workflow and its result contract. `AptlOrchestrator`/`WorkflowEngine` produce the state; `LocalRunStore` validates paths and redacts structured writes. The assertion may discover the one run directory, but must parse the one expected workflow with the RAES contract model rather than trusting filenames or hand-validating JSON. |
| Error envelopes and logs | Backend failures remain bounded `Diagnostic`/`LabResult` failures. Shell assertions may emit safe identifiers and expected/actual non-secret states, but must not dump environment, full inspect payloads, generated config, tracebacks, or run archives. |
| Cleanup and persistence | Both stop and the independent absence proof remain `always()`. Cleanup stays project-scoped and includes stopped containers, networks, and volumes. Run files live only under the runner's temporary materialized project; do not upload them or add a qualification database. |

## Coverage Map

This is a short, human-maintained map until #1126 derives coverage from the
canonical manifest and envelope. It must not become a second capability
registry.

| Advertised concern or capability | Existing tests and bounded boot posture |
| --- | --- |
| `compute-substrate`, `operating-system`, `topology`, `network` | The current shared fixture and installed boot exercise these together. Focused failure/readback coverage lives in `test_raes_base_substrate.py`, `test_compose_base_substrate.py`, `test_deployment_backend.py`, and `test_raes_observation.py`. |
| `content-placement` | Focused policy, lowering, ordering, and fail-closed observation live in `test_content_realization_source_policy.py`, `test_raes_materializer.py`, `test_raes_materializer_engine.py`, and `test_raes_observation.py`. Issue #993 adds one live causal content effect to the shared boot. |
| `service`, `runtime-service-manager-units`, `service-listeners`, `published-ports` | Focused lowering and negative readback cases live in `test_imagefree_admission_integration.py`, `test_raes_runtime_observation.py`, `test_raes_realization_service_ports.py`, and `test_compose_port_realization.py`. Issue #993 makes one service/listener/loopback-port chain live in the installed boot. |
| `runtime-packages`, `runtime-local-identity`, `runtime-filesystem-inventory` | Already observed by the installed boot, with focused read-after-write and mismatch cases in the materializer and runtime-observation suites. |
| Orchestrator `workflows` capability | `test_raes_orchestrator.py`, `test_workflow_engine.py`, and `test_raes_backend.py` own contract and failure cases. Issue #993 adds one terminal persisted workflow effect; it is not a realization-envelope concern. |
| `architecture`, `image`, `resource-allocation` | Focused image/platform, daemon-readback, and limit tests exist, but the small boot makes no explicit coverage claim for these concerns. |
| `account-placement`, `acl` | Provider and owner-scoped negative/positive tests exist in `test_deployment_backend.py` and `test_raes_acl_realization.py`; they remain untested by the generic installed boot. |
| `feature-binding` | The realization envelope advertises it as unsupported. There is no positive boot claim. |
| Generated artifacts, persistent volumes, service-search-index materialization, forwarding agents, dependency manifests, software components, the remaining daemon runtime concerns, and `runtime-orchestration-authorities` | Focused unit/integration or TechVault tests remain authoritative. They are explicitly outside this boot. #1126 owns automatic identification of any advertised concern without adequate coverage. |

Structural tests should continue to prove that the existing job uses the shared
fixture, scopes native inspection, parses the workflow contract, runs stop and
cleanup under `always()`, and retains its timeout. They must not merely grep for
new assertion strings while the corresponding SDL field is absent.

## Extensibility And Whole-Repository Scope

The extension seam is the existing fixture plus a bounded verifier
parameterized by the validated project name, admitted node address, expected
loopback/container port tuple, and workflow address. Those values are safe
identities, not a new realization schema. The next small regression can add one
fixture field and one effect assertion without another CI job or scenario.
Automatic enumeration, concern-to-assertion metadata, or a general coverage
registry waits for #1126.

The repository surfaces in scope are the shared SDL and all of its consumers;
the Checks workflow and its stable job context; wheel asset construction and
materialization; RAES manifest/envelope, parser, planner, provisioner,
orchestrator, and observation gates; generic base Dockerfiles and build-context
asset inventory; strict config/env handling; Docker ownership, listener/port
inspection, and cleanup; run-store persistence; and the focused pytest suites
named above. The implementation should not change a Dockerfile or configuration
asset merely to make this test convenient; doing so would trigger the separate
clean-machine validation rule in `.gc/plan-rules.md`.

## Gotchas And Anti-Patterns

- Do not add a second boot job, a second near-identical SDL, or a TechVault
  service to this fixture.
- Do not claim content coverage from file existence alone when the selected
  regression is content needed by the service. Make the listener depend on it.
- Do not claim service coverage from container state, package installation, or
  a declared `services` entry. Observe the unit and the live listener.
- Do not claim port readback from authored YAML or rendered Docker arguments.
  Inspect the project-owned container, require the exact loopback tuple, and
  connect to it.
- Do not conflate container target ports, Docker host ports, endpoint-registry
  ports, or MCP client ports. This fixture exercises the first two only.
- Do not parse workflow JSON with a duplicate schema, accept `PENDING`, or infer
  success from a result filename. Require the RAES terminal state and history.
- Do not select `runtime.orchestration_authorities`, mount a Docker socket, or
  pull worker images to exercise the ordinary workflow adapter.
- Do not expose the listener on `0.0.0.0`, add a test credential, print config
  content, or pass content through process argv.
- Do not use daemon-wide prune, broad name matching, or best-effort cleanup.
- Do not grow the fixture across every advertised concern; that is #1126 and
  would violate the practical-budget and single-scenario constraints here.

## Non-Goals

Issue #993 does not redesign RAES schemas, the realization envelope, runtime
DTOs, deployment backends, auth, config, exception hierarchies, logging,
telemetry, or persistence. It does not qualify TechVault, runtime Docker
authority, spawned workloads, participants, generated credentials, remote
Docker, non-Linux hosts, or every supported realization concern. It does not
replace the shared contract work in #1099 or automatic envelope coverage in
#1126, and it does not change branch protection or add another required check.
