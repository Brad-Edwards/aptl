# Boot realization coverage

APTL publishes a `realization-envelope-v1` disclosure naming every realization
concern it claims to realize and observe
(`src/aptl/backends/raes_realization_envelope.py`). This page maps those claims
to the tests that hold them, and states plainly which the small installed-wheel
boot gate does **not** cover.

It is short and maintained by hand. Deriving coverage automatically from the
envelope is tracked in issue #1126; this table must not grow into a second
capability registry.

The **Clean-install lab boot and teardown (DEP-008)** job starts the one
product-neutral scenario, `tests/fixtures/materialization-envelope.sdl.yaml`.
Since issue #993 that scenario carries a single causal chain: inline content
moves the SSH daemon off its package default port, the declared service unit
starts the daemon, the declared listener binds the moved port, and that port is
published on an exact loopback host binding. A content placement that silently
did not happen therefore fails the listener, the port and the endpoint checks
with it. `scripts/ci/assert_boot_realization.py` makes every one of those
checks observe an effect in the running lab rather than a declaration.

## Advertised concerns

| Concern | Covered by |
| --- | --- |
| `compute-substrate` | Boot gate (the node's container runs). Focused: `tests/test_compose_base_substrate.py`, `tests/test_raes_base_substrate.py` |
| `operating-system` | Boot gate (the substrate is selected by declared family). Focused: `tests/test_raes_observation.py` |
| `topology`, `network` | Boot gate (the scenario's isolated network). Focused: `tests/test_compose_boundary_realization.py`, `tests/test_network_boundary_helper.py` |
| `content-placement` | Boot gate, live and causal (exact placed bytes, read inside the container). Focused: `tests/test_content_realization_source_policy.py`, `tests/test_raes_materializer.py`, `tests/test_raes_materializer_engine.py` |
| `account-placement` | Boot gate observes the declared local user and group. Focused: `tests/test_deployment_backend.py`, `tests/test_account_provider.py`. Directory and domain account features stay outside the boot |
| `service` | Boot gate, live (`UnitFileState`, `ActiveState`, `Result` read from the service manager). Focused: `tests/test_imagefree_admission_integration.py` covers the dnf substrate, `tests/test_raes_runtime_observation.py` the observation cases |
| `resource-allocation` | Focused only: `tests/test_raes_runtime_environment.py`, `tests/test_compose_resource_ownership.py`. The boot gate makes no claim |
| `image` | Focused only: `tests/test_docker_image_identity.py`, `tests/test_raes_docker_materializer.py`. The boot scenario is image-free, so the boot gate makes no claim |
| `architecture` | Focused only: `tests/test_raes_observation.py`. The boot gate makes no claim |
| `acl` | Focused only: `tests/test_raes_acl_realization.py`. The boot gate makes no claim |
| `feature-binding` | Disclosed `unsupported`. There is no positive claim to cover |

## Beyond the envelope

| Capability | Covered by |
| --- | --- |
| Declared service listeners | Boot gate, live, read from outside the container's trust boundary. Focused: `tests/test_declared_listener_readiness.py`, `tests/test_proc_net_listeners.py` |
| Host-published ports | Boot gate, live: the exact declared loopback tuple, no wider binding, and a real connection. Focused: `tests/test_compose_port_realization.py`, `tests/test_docker_compose_port_bindings.py` |
| Orchestrator `workflows` | Boot gate, live: one end-only workflow driven to a terminal RAES state with history, parsed with the contract model. Focused: `tests/test_raes_orchestrator.py`, `tests/test_workflow_engine.py` |
| Lifecycle and teardown | Boot gate: `aptl lab stop --volumes` plus the independent project-scoped absence proof in `scripts/ci/assert_project_teardown.py` |
| The gate's own failure modes | `tests/test_boot_realization_gate.py` — every check fails closed without Docker |

## Declared dimensions APTL does not read back

SEM-218 forbids a silent approximation, so APTL refuses to corroborate a
declared dimension it cannot observe, and the RAES handoff then fails the whole
lab start rather than reporting a realized range. Two consequences worth
knowing before extending the fixture:

- A service unit may declare only the dimensions the service manager is asked
  for — load, enabled and active state. `unit_type`, `unit_file_path`,
  `exec_start` and a `Node.services` back-reference are not read back
  (`_service_unit_shape_supported` in
  `src/aptl/backends/raes_runtime_guest_observation.py`), so declaring one
  fails the boot. `tests/test_boot_realization_gate.py` holds the shipped
  fixture to that shape at unit speed rather than at boot speed.
- A filesystem entry may not declare a content digest, digest algorithm,
  source path or provenance for the same reason
  (`_filesystem_shape_supported`).

These are honest gaps in observation, not defects in the gate. Widening them
means teaching the backend to read the dimension back, which is outside this
page's scope.

## Explicitly outside the small boot

The boot gate is deliberately one small scenario. It does not cover generated
artifacts, persistent volumes, service search-index materialization, forwarding
agents, dependency manifests, software components, identity authorities,
participants, `runtime.orchestration_authorities` (a host-root-equivalent
Docker authority surface governed by ADR-055), remote Docker endpoints, or
non-Linux hosts. Focused unit and integration suites remain authoritative for
those, and full-range qualification is tracked in APTL #870 and #685 and in
OpenRAE/lilrae #4, #9, and #10.

Adding the next regression should add one field to the shared scenario and one
effect assertion to the verifier — not a second boot job and not a second
scenario.
