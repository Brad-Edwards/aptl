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
product-neutral scenario,
`tests/fixtures/packs/materialization-envelope/sdl/materialization-envelope.sdl.yaml`.
It is the scenario of APTL's owned [lab fixture pack](lab-fixture-pack.md),
which the unit suite admits through the same resolver as a released pack. The
job itself selects the SDL by explicit path, so it covers the installed
lifecycle, not pack admission.

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
| `service` | Boot gate, live (`UnitFileState`, `ActiveState`, `Result` read from the service manager) on the apt/Debian systemd substrate. Focused: `tests/test_raes_materializer.py` pins substrate selection per package family, `tests/test_raes_runtime_observation.py` the observation cases |
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
| Lifecycle and teardown | Boot gate: `aptl lab stop --volumes` plus the independent absence proof in `scripts/ci/assert_project_teardown.py`, scoped to the project and diffed against a pre-start daemon baseline for anonymous volumes and helper containers. Focused: `tests/test_assert_project_teardown.py`, `tests/test_ephemeral_containers.py`, and `tests/test_container_lifecycle_policy.py`, which fails on any helper or container removal that bypasses the shared policy |
| The gate's own failure modes | `tests/test_boot_realization_gate.py`, where every check fails closed without Docker |

## Declared dimensions APTL does not read back

SEM-218 forbids a silent approximation, so APTL refuses to corroborate a
declared dimension it cannot observe, and the RAES handoff then fails the whole
lab start rather than reporting a realized range. Two consequences worth
knowing before extending the fixture:

- A service unit may declare only the dimensions the service manager is asked
  for: load, enabled and active state. `unit_type`, `unit_file_path`,
  `exec_start` and a `Node.services` back-reference are not read back
  (`_service_unit_shape_supported` in
  `src/aptl/backends/raes_runtime_guest_observation.py`), so declaring one
  fails the boot. `tests/test_boot_realization_gate.py` holds the shipped
  fixture to that shape at unit speed rather than at boot speed.
- A filesystem entry may not declare a content digest, digest algorithm,
  source path or provenance for the same reason
  (`_filesystem_shape_supported`).

## The dnf/RHEL systemd substrate has no live coverage

A service node in the `rhel` package family selects
`aptl/generic-systemd-base` rather than the Debian substrate the boot scenario
uses. That selection is a pure lookup, pinned by
`tests/test_raes_materializer.py::test_service_nodes_use_family_aware_systemd_substrate`,
which runs in CI. What nothing proves is the live fact: that Rocky's systemd
boots under APTL's init flags and runs a declared unit.

A second live scenario used to assert that and was retired in issue #993. It
ran in no CI job, no shipped scenario declares a dnf node, and it re-asserted
the generic admission contract the shared fixture already covers. Restore live
coverage when a scenario actually declares a `rhel` service node, and prove it
through that scenario's own gate rather than a second generic fixture.

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
effect assertion to the verifier, not a second boot job and not a second
scenario.
