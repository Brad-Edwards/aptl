# Issue #958: Execution Boundary Preflight

This is architecture guidance for the issue, not an implementation plan. The
issue's title, body, and acceptance criteria are the shipping contract. ADR-049
describes the broader participant architecture; ADR-060 narrows the current
optional seat to VM-only containment. Ordinary `aptl lab start` runs against
the selected Docker daemon and may be local, VM-backed, remote, or unclassified.

## Decisions and boundaries

- Report three separate facts: **selected deployment transport/daemon**,
  **observed host containment**, and **scenario-visible realized node form**.
  A Docker VM on a remote host is not a VM containing the CLI's physical host;
  a seat VM is not a scenario VM. Do not infer one fact from another.
- Compose one bounded, request-scoped boundary observation from owner-produced
  facts: the deployment backend observes its effective Docker endpoint; the
  seat launcher supplies its independently authenticated outer-host evidence.
  `aptl lab start` and `aptl lab info` should project that same
  observation into their existing CLI presentation, including an explicit
  `unknown` result and a visible configured/observed mismatch. Re-observe for
  `info`; a saved start label can be stale after context, daemon, or seat change.
  Treat unreadable daemon data as unknown, never as native or contained. A
  failed start should still report that attempt's trustworthy observation or
  unknown.
- Keep a static **capability** claim distinct from the **selected run** and its
  evidence. `raes_manifest.create_aptl_manifest()` and its RAES
  `backend-manifest/v2` conversion are the canonical capability publishers;
  the applicable RAES disclosure contract must carry the selected boundary,
  limits, observation status, and exact evidence/profile reference. Use a
  contract-supported field or versioned extension validated by RAES; do not
  hide runtime facts in free-form `constraints`, change the scenario realization
  envelope's meaning, or invent an APTL-only duplicate manifest. An unsupported
  contract shape is a coordination blocker, not permission to drop disclosure.
- A **required** containment profile is a conjunctive admission gate. Resolve
  its requirement from the admitted owner contract, then resolve the selected
  backend and, where applicable, signed seat policy. Do not reinterpret an
  authored scenario VM/container requirement as a host-containment demand or
  let an operator option weaken a required profile. Check the effective endpoint
  and qualification evidence, then refuse unsupported, unknown, or unverified
  containment (including an override outside the qualified profile) before
  startup mutation. The `start --clean` path must refuse before its `stop_lab`
  teardown; the gate belongs in shared core admission so API and CLI starts
  agree. `stop`, `status`, and `info` remain available for recovery and
  observation when admission fails. Optional containment may be
  reported as unverified; it must never silently weaken scenario behavior.
  Continue to let RAES plan and verify authored VM/container requirements.
- Containment evidence is profile-specific: identify OS/runtime versions,
  daemon/transport, image and policy digests, host/guest resource allocation,
  device/network exposure, test kind, and result for the exact claimed profile.
  A Docker Desktop, Colima, QEMU, or KVM name, a signed image, a unit test, or
  successful scenario readiness alone proves no host containment property.
  Document unsupported workloads and unknown/untested combinations explicitly.

## Canonical incumbents and cross-cutting passage

| Layer | Required use and guardrail |
| --- | --- |
| Selection and config | `AptlConfig.DeploymentConfig`, `get_backend()`, `resolve_config_for_cli()`, and the strict `aptl.json` loader own provider and project shape. `SSHComposeBackend` validates its SSH fields. Do not add unvalidated provider aliases or a second config parser. |
| Effective Docker endpoint | `DeploymentBackend`, `HostInventoryBackend`, `DockerComposeBackend._run()`/`docker_transport_environment()`, `_docker_endpoint_binding.py`, and `host_versions()` own daemon operations. Account for `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, SSH transport, rootless Unix sockets, and seat-pinned sockets. Probe via the effective backend, with argv lists and finite timeouts; respect `supports_local_artifacts` for SSH; never infer from the local shell alone. |
| Host and seat policy | `core/hostenv.py`, `sysreqs.py`, `appliance/seat/{prereqs,image_config,exposure,observation,readiness,vm}.py`, `core/appliance_boundary.py`, `appliance_boundary_inventory.py`, and `appliance_boundary_gate.py` own OS/tool observations, signed V2 policy, mappings, VM launch exposure, and live host/guest proof. Reuse their closed models and gate; do not turn a seat record, PID, listener, or signed digest into fresh proof. |
| Startup and CLI | `core.lab`'s ordered `_step_*` lifecycle, `LabResult`/`StartupDiagnostic`/`StartupOutcome`, `cli/lab.py`, and `cli/lab_render.py` own failure and presentation. Keep `info` live and read-only. Required-containment failure is terminal, not `degraded_usable`; never run cleanup or scenario deployment first. |
| RAES and scenario | `backends/raes_manifest.py`, `raes_realization_envelope.py`, `raes.py`, `core/experiment/{apparatus,admission}.py`, RAES parsing/planning, and existing realization observations own capability and scenario materialization. Do not conflate host containment with authored compute substrate, guest OS, or scenario network isolation. |
| Auth and errors | `api/main.py`, `api/deps.py`, `api/schemas.py`, and `api/routers/lab.py` own HTTP auth and typed response envelopes if boundary facts later reach the API/web. Preserve BFF, bearer/session, origin/CSRF and SSE gates; never add an unauthenticated diagnostic route. Use existing `BackendObservationError`, `LabResult`, and narrow API errors, with bounded public messages. |
| Secrets, OS exposure, persistence | `core/env.py`, `utils/strict_json.py` for signed/security-sensitive JSON, `utils/redaction.py`, `utils/logging.py`, `LocalRunStore`, provenance apparatus/runtime-facts providers, and seat private state own parsing, redaction, logs, and records. `core/host_ports.py`, `docker-compose.yml`, and seat exposure/mapping checks own actual publications, daemon-socket mounts, and VM device/network exposure; a mounted Docker socket grants daemon authority. Do not print Docker config paths with credentials, SSH identity paths, environment dumps, raw daemon/QEMU stderr, tokens, or command lines. This reporting path must put no credentials in argv, URLs, public manifest fields, or evidence links. Persist only bounded, redacted facts and immutable evidence references through the existing run/provenance contracts. |
| Evidence and docs | `docs/reviews/1162-seat-acceptance.md` documents one real Linux/KVM host but lacks a complete host/QEMU version inventory; `docs/testing/issue-956-candidate-*-manual-qa.md` documents Ubuntu 24.04, Python 3.12.3, Docker Engine 29.5.0, Compose 5.1.3 for candidate lab QA. `README.md`, `docs/getting-started/{quick-start,prerequisites}.md`, `docs/deployment.md`, and `docs/reference/appliance-seat-launcher.md` must state tested profiles, exposed host resources, prerequisites, and unsupported workloads without expanding these records into untested platforms. |

## Specific risks and extensibility seam

`hostenv.docker_mode()` currently classifies a Linux CLI host plus a non-Desktop
Linux daemon string as `linux_native`; it does not establish that the daemon is
local. `sysreqs.check_max_map_count()` consumes that classification. A context
or SSH override can therefore make a host sysctl check and a boundary label
refer to different machines. Observe endpoint provenance and daemon identity
before classifying; unknown or conflicting evidence stays unknown. The same
backend-selected observation should feed CLI, admission, and RAES disclosure so
those surfaces cannot disagree. `provenance.providers.runtime_facts` also
records ambient `docker_mode()` today; that field cannot be reused as proof of
the selected daemon's containment.

An admission-time daemon probe cannot attest a different daemon used later:
bind and revalidate the effective endpoint at deployment, using the existing
seat socket/daemon binding where applicable. A context, socket, or daemon
change must invalidate a required profile rather than reuse a prior verdict.

`cli/lab.py:info` currently exits when `.env` is absent, before any boundary
observation. `cli/lab_render.py` also has an access-port fallback when live
bindings are unavailable. Neither credential-file presence nor a guessed port
is evidence of the execution boundary or host exposure. Keep the boundary
readback useful for a stopped, partial, or unobservable project, and distinguish
live published ports from planned/default ports. A remote daemon's published
ports belong to the remote host, not automatically to the CLI host.

The extension seam is a validated boundary profile/observation carrying
transport, effective daemon identity, outer containment mode, observation
completeness, resource/exposure limits, and evidence references. A later Docker
VM or seat adapter contributes an observation and matching evidence at that
seam; it does not require new CLI classification branches, scenario schemas,
or a different backend manifest for each host. Keep static capability and
per-run profile data distinct under the RAES contract's versioning rules. If
the accepted RAES or seat contract cannot express a required profile or its
run-specific disclosure, extend that owner contract before claiming support;
do not smuggle the value into an APTL-only field.

## Whole-repository scope and non-goals

Inspect the canonical runtime/config/seat/RAES surfaces above together with
`docker-compose.yml`, `config/`, `containers/`, `appliance/guest/`,
`.ground-control.yaml`, `.gc/plan-rules.md`, and focused CLI, hostenv,
backend, seat, manifest, and admission tests. Compose and image changes require
their existing fresh-lab CI gate; local testing stays targeted with staged-file
`pre-commit run`.

This issue does not build a new seat, certify every OS/runtime combination,
change RAES-authored topology or VM/container requirements, enforce deferred
internal guest zones from #1127, alter API authorization, or introduce another
config, exception, persistence, or evidence schema. Avoid a static
"Docker means contained" banner, a generic `is_vm` flag, a best-effort
fallback after failed required containment, and documentation that turns one
machine's successful QA into a general security guarantee.
