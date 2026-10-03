# Issue #1194 Shipped Seat Network Preflight

The supplied [issue #1194](https://github.com/Brad-Edwards/aptl/issues/1194)
is the acceptance contract. This note sets implementation boundaries, not an
implementation plan or an incident finding. No new ADR is needed: ADR-025,
ADR-029, ADR-030, ADR-037, ADR-046, ADR-060, and ADR-061 already own the relevant
configuration, secret handling, outcomes, backend, realization, and seat
contracts. ADR-055 remains proposed; the implemented ownership receipts are
the incumbent authority mechanism.

## Evidence And Concept Boundaries

Keep four independent facts distinct:

- **Delivery identity:** OCI manifest digest, disk/config digests, embedded
  software and dependency revisions, and overlay/deployment changes.
- **Docker selection:** effective daemon, transport, context/environment, socket
  identity, privilege mode, Engine version, and cgroup capability.
- **Scenario topology:** admitted scenario links, addresses, aliases, network
  policy, and their actual container endpoints.
- **Outer networking:** the host's rootless QEMU namespace, slirp4netns, QEMU
  NAT, and participant gateway publication. These do not establish guest
  rootless Docker or container attachments.

The supplied historical facts establish that v5.5.0/v6.0.0 omitted image-free
post-materialization reconciliation and that #1170 supplies it. Current
At assessment time, `_compose_realization.py` called
`reconcile_image_free_networks()` and propagated its failure before
platform-boundary realization. The implementation now replaces that wrapper
with the same `_reconcile_declared_networks()` result method used by the
mixed/Compose path. Existing code also has
pre-create network binding in `_compose_base_substrate.py` and
`_compose_image_free_realization.py`. A successful current-tree boot therefore
cannot isolate the effect of #1170 or certify the delivered image.

The current bake enables guest `docker.service` and grants the desktop account
guest Docker access. ADR-060 describes rootful guest Docker; ADR-061 describes
a rootless *host namespace*. Neither verifies what heron1 actually selected.
`DockerEndpointBindingMixin` honors a local Unix `DOCKER_HOST`, otherwise binds
the system socket, and its runner clears `DOCKER_CONTEXT` when pinned. Record
effective backend selection, not just `docker context show` in another shell.
First boot runs with `HOME=/var/lib/aptl`; the desktop uses `/home/aptl`.
Probe differences across service, desktop, and backend binding explicitly.

Default startup resolves the configured `ScenarioSourceConfig` (normally the
acquired `techvault` env-pack) through `resolve_scenario_bundle()`. Explicit
`--scenario-path` wins and selects a project-tree bundle. The bounded scenario
declares packages, systemd units, links, and static addresses. Capture its
actual admitted/lowered spec and `_needs_compose()` decision; do not infer
routing from the word TechVault, filename, package declaration, or release tag.

Incident evidence must bind the delivered image to its build record, baked
`APTL_SEAT_COMMIT`, actual installed entrypoint/wheel, dependency/pack versions,
scenario bytes and selection, launch/overlay generation, and relevant operator
or deployment changes. OCI manifest and qcow2 digests are different identities;
`:latest`, a version string, or a source-commit assertion alone is insufficient.
Missing provenance stays unknown. Preserve the operator's report; do not
attribute the failure to participant misconfiguration without evidence.

Obtain the exact corrective command/setting when available and classify its
effect among these boundaries. Compare a disposable baseline matching the
delivered image with the same reproduction containing #1170, retaining all
other relevant inputs. If that patch needs prerequisites, disclose them and
bound the causal claim. Record why the delivery gate missed the proven failure
and which immutable software/image correction is required. Do not duplicate
#1170 when it fully resolves the incident. Unknown correction details or an
unavailable historical image limit conclusions. The owner instructed this run
to proceed using available evidence because nobody knows the missing incident
details. A controlled network-boundary experiment on the matching retained
disk, with its limitations stated, replaces the unavailable historical replay;
see [the investigation record](../reviews/1194-seat-network-investigation.md).

Heron1 is occupied: no service restart, context switch, container reconnect,
guest-config edit, cleanup, or overlay replacement without separate
authorization. Prefer existing evidence and disposable environments. The
[issue #1188 note](issue-1188-wazuh-api-cold-boot-preflight.md) describes
post-intervention seat evidence without a pristine baseline; it is not proof
of this incident's original state or permission for another intervention.

## Canonical Owners And Required Passage

Runtime module paths below are relative to `src/aptl/` unless shown in full.
Deployment helper basenames live in `core/deployment/`; RAES helper basenames
live in `backends/`. Guest scripts (`appliance/guest/`) and other paths are
repository-relative. These are the layers the intended change must satisfy,
including guards outside the eventual edited file.

| Layer | Incumbent and required guardrail |
| --- | --- |
| Image trust and delivery | `scripts/appliance/{build-seat-image.sh,seat-build-record.py,publish-seat-image.sh}`, `src/aptl/appliance/seat/{image.py,image_trust.py,image_selection.py,retained_image.py}` own construction, byte binding, Cosign admission, sticky selection, and retained generations. Reuse them; qualification evidence must name the exact tested bytes. Signatures authenticate content, not successful qualification. Package updates and tag promotion do not update a selected image or installed guest automatically. |
| Signed shapes and containment policy | `utils/strict_json.py`, `appliance/seat/image_config.py`, `appliance/seat/launch_descriptor.py`, and `core/appliance_boundary.py` own strict JSON, closed models, policy generations, and exact loopback publication mappings. New fields must enter their owning model and consumer together; revalidate external values. Never reinterpret old signed bytes or bypass these validators with environment toggles. Scenario networks are not deferred internal security zones under VM-only policy. |
| Scenario admission and lowering | `core/config.py`, `core/scenario_bundle.py`, `backends/_raes_scenario_resolution.py`, `raes_realization.py`, `raes_realization_networks.py`, `raes_realization_model.py`, and `core/deployment/realization.py` own selection, contained bundle paths, RAES interpretation, CIDR/gateway/static-address validation, and `DeploymentNetworkAttachment`. Preserve links and per-network addresses through lowering; reuse the RAES parser/planner and these models instead of another YAML/network schema or shell parser. |
| Environment and secrets | `backends/scenario_startup.py`, `_scenario_environment.py`, `scenario_runtime_parameters.py`, and `core/env.py` own exact-pack provider compatibility, alias/fixture shapes, valid environment names, and dotenv handling. Keep Docker transport in the backend runner, not pack credential aliases or ambient secret grants. Preserve the explicit control-plane env source in `_build_command()`. Reuse `core/credentials.py` and `utils/pathsafe.py` for generated private files. Never collect whole environments, Docker auth/config files, MCP configs, or `/home/atomik/.secrets` / `~/.secrets`. |
| Endpoint and runtime security admission | `_docker_endpoint_binding.py`, `docker_compose.py`, `_compose_runtime_materialization.py`, `runtime_materialization.py`, and `_compose_substrate_gate.py` own effective transport, socket/daemon binding, runtime shape/authority checks, and substrate support. Use the selected backend's runner for probes and revalidation. The current systemd gate requires cgroup v2, Engine >= 28.0, and rejects rootless/userns-remap; binding a rootless Unix socket is not substrate qualification. Preserve ordered rejection and diagnostics rather than adding privileged or host-cgroup fallbacks. Inspect the historical revision's gate separately. |
| Resource authority and reconciliation | `_compose_resource_ownership.py`, `_compose_owner_labels.py`, `_compose_project_inventory.py`, `_compose_network_conflicts.py`, `_compose_node_topology.py`, `_compose_realization_networks.py`, `_compose_network_realization.py`, and `_compose_image_free_network_reconciliation.py` own receipts, native-ID scoping, naming, subnet conflicts, pinned/dynamic address pools, policy reuse, aliases, and reconciliation. Resolve the expected networks and containers on the same daemon using verified receipts; names and labels alone do not authorize mutation. Unknown/foreign state fails without guessed repair. |
| OS execution and exposure | `DockerComposeBackend._subprocess_kwargs()`, `_run()`, and `_run_with_input()` own list-form argv, effective environment, timeouts, and stdin delivery. Keep credentials out of argv, URLs, logs, and exception text; use bounded allow-listed observations. Guest systemd/desktop files and `appliance/seat/{namespace.py,vm.py,exposure.py}` own process/user and publication boundaries. Preserve guest-owned Docker, private launch shares, per-user state, and host/cross-seat protections; add no socket mount or wildcard listener for diagnostics. |
| Errors, logging, and public projections | `core/deployment/errors.py`, `core/lab_types.py`, `core/lab.py::_emit_diagnostic`, `backends/raes_diagnostics.py`, `utils/{logging.py,redaction.py}`, and `core/execution_boundary.py` own safe errors, startup outcomes, RAES diagnostics, and bounded daemon disclosure. Reuse `BackendTimeoutError`, `BackendObservationError`, `BackendSeedError`, `OwnershipConflictError`, `LabResult`, and `StartupDiagnostic`; missing required attachments must not become ready or cosmetic success. Some network failures currently include Docker stderr: sanitize at every exit, including RAES failure details, rather than assuming `_emit_diagnostic` sees all paths. Do not publish raw inspect, endpoint URIs, tracebacks, or environment values. |
| Auth and readiness | `appliance/guest/{desktop-nginx.conf,seat-desktop.py,desktop-handoff.py,desktop-mcp-smoke.py}`, `appliance/seat/readiness.py`, and `appliance/guest_observation.py` own trusted gateway identity, private per-overlay credentials, MCP handoff shapes, challenge/generation binding, and fresh guest observations. Preserve them; network repair must not weaken SSH host-key/TLS/auth checks to make red or blue connect. The legacy API retains `api/deps.py` auth and `api/schemas.py` response contracts if touched; new desktop seats do not acquire another API or host-MCP auth flow. |
| Persistence and lifecycle | `appliance/seat/{models.py,persistence.py,overlay_identity.py,locking.py}`, `core/runstore.py`, and `core/lifecycle_*` own atomic private state, generations, run records, locks, sealing, and cleanup. Store bounded incident evidence through existing paths and redact structured writes; do not rewrite sealed runs, ownership receipts, or live readiness. Preserve failure/residual-resource evidence and use existing owned cleanup in disposable tests, including stopped containers. |

## Readback And Regression Boundary

Reconciliation success is not topology readback. On the same verified daemon,
observe every expected node's declared network membership, exact static IPs,
required DNS aliases, and network CIDR/gateway/internal policy. Distinguish
uninspectable state from a valid empty inventory; neither satisfies a required
attachment. Network existence and container-running state alone are inadequate.
Reuse `_compose_realization_networks.py` resolution and native inspect paths;
if production readback has a gap, extend the existing observation/reconciliation
owner rather than adding a qualification-only repair loop.

Preserve #1170's published-port exception: an implicit default bridge may remain
where publication depends on it. The required assertion is declared attachments
and working intended ports, not blanket absence of `bridge`. Cover missing
networks, lost lowering, wrong/empty IPs, alias drift, policy/subnet conflicts,
foreign ownership, command failure, and unreadable/changed daemon identity.
Unsupported exact combinations must name the failed capability and supported
alternative without silently changing daemon, scenario, addresses, or policy.

`tests/test_compose_base_substrate.py` already covers the #1170 call/failure
contract. `test_deployment_backend.py`, `test_substrate_daemon_gate.py`,
`test_compose_substrate_attestation.py`, `test_runtime_materialization.py`,
`test_execution_boundary.py`, and RAES realization/observation tests own focused
network, authority, and lowering regressions. Seat bake/runtime/desktop tests
own provisioning and session handoff contracts. Extend the relevant incumbents
according to the proven failure, with negative cases that detect false readiness.

`scripts/ci/assert_boot_realization.py` and the installed-wheel boot job in
`.github/workflows/checks.yml` exercise the shared minimal fixture; they do not
certify heron1 or the bounded scenario. `scripts/appliance/qualify-seat-image.sh`
uses a disposable overlay but disables actual first boot and substitutes
`seat-qualification-smoke.service`. Its shell defaults, MCP checks, and
stop/start cycle alone do not prove signed launch, desktop-user selection, or
the explicit bounded scenario's attachments. Regression qualification must
exercise the delivered workflow in a matching disposable seat, default
TechVault and explicit bounded selection separately, with actual readback and
participant reachability. Retain this useful smoke path without claiming it is
full participant-path evidence. Do not modify the golden just to instrument it
and then claim those changed bytes were delivered.

Keep local verification targeted through `tools/run-targeted-tests.sh` and
staged `pre-commit run`. Full suites, coverage, long VM/live gates, and clean lab
lifecycle qualification belong in CI/CD under `.ground-control.yaml` and
`.gc/plan-rules.md`. CI cleanup must execute on failure and remain owner-scoped;
never use daemon-wide prune or collect unrestricted run archives as artifacts.

## Extensibility, Non-Goals, And Anti-Patterns

The extension seam is the existing backend transport plus qualification inputs
for immutable image/revision, validated scenario selection/bundle, and expected
topology derived from `DeploymentRealizationSpec`. Keep service versus desktop
execution identity explicit. A second scenario or image should change admitted
inputs, not require editing hardcoded TechVault addresses or creating another
daemon detector, schema, image builder, or startup controller. Pack-specific
behavior stays behind the exact `PackIdentity` startup provider; generic network
attachment semantics stay in the deployment backend.

Whole-repository scope includes seat build/publish/acquisition and retention;
guest provisioning, first boot and desktop sessions; strict config and env-pack
selection; RAES admission/lowering/observation; Compose and generic-substrate
routes; Docker endpoint, ownership and networking; participant MCP handoff;
readiness/outcome/error projections; private persistence; and canonical test,
qualification, release and workflow rules. Compare each historical incumbent
at the delivered revision instead of assuming current-tree behavior.

Non-goals are new rootless/systemd support, daemon-global bridge rewrites,
automatic context switching, internal-zone/egress redesign (#1127/#1182),
terminology redesign (#1193), duplicate #1170 implementation, and live-seat
remediation. Do not patch rendered `.aptl/realization` files, edit signed
artifacts, substitute a simpler scenario, add retry/repair logic in provisioning
or desktop shells, bypass offline admission by pulling dependencies, or loosen
validators to obtain a green test. Preflight authorizes guidance only; incident
reproduction, a remaining code fix, regression implementation, and shipment
belong to the subsequent issue work.
