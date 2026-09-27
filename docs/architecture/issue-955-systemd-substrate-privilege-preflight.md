# Issue #955 Generic Systemd Substrate Privilege Preflight

This note fixes the design boundary for reducing the generic systemd substrate's
host authority. It is guidance, not an implementation plan. No ADR is needed:
ADR-048 already assigns generic substrate selection and realization to the
backend, ADR-046 requires bidirectional runtime parity, and ADR-055/ADR-060
separate Docker authority from the outer appliance boundary. The branch already
contains part of the #955 change; the rules below apply to that code as well as
the remaining qualification and clean-range proof.

## Architecture Decisions

### Keep init intent separate from container-security mechanism

`runtime.service_manager_units` selects a generic systemd base. That selection
alone authorizes none of the retired host cgroup, unconfined seccomp, or added
capability recipe. The default `InitRequirements` is the code-owned init
baseline; the same typed spec may also carry separately authored
`runtime.linux_capabilities.add` values and a measured backend provider grant.
Keep those three sources distinguishable. Issue #956's fidelity contract does
not authorize an APTL content allowlist that strips or rejects valid authored
privilege on the normal lab path: RAES validates meaning and the selected
backend qualifies faithful lowering and readback. The secure seat's outer VM
boundary is separate.

The supported generic-systemd substrate is cgroup v2 on Docker Engine 28.0 or
newer. Before any generic systemd image build, network creation, or container
removal, the selected deployment backend must query the *target Docker daemon's*
cgroup version and engine version using its existing argv-list runner. It must
fail closed with one bounded `LabResult`/`BackendSeedError` diagnostic when
either probe fails, is unparseable, or reports an unsupported value. The cgroup
probe must come first: `writable-cgroups=true` on cgroup v1 would expose a
writable host-sensitive cgroupfs. Do not retain a cgroup-v1 compatibility branch
in this issue: it would create a host-dependent privilege baseline and a second
readback policy. Request `--cgroupns=private` explicitly so the inspected
contract is deterministic.

`InitRequirements` must therefore describe one v2 posture: private cgroup
namespace, `writable-cgroups=true` on its namespace-scoped cgroup2 mount, no
host `/sys/fs/cgroup` bind mount, existing private `/run`, `/run/lock`, and
`/tmp` tmpfs needs, Docker's default seccomp and AppArmor profiles, and no
blanket added capabilities. A backend-added init capability may return only as
a documented, per-substrate necessity proved for every selected systemd base
(including layered Node/Wazuh variants) and the affected declared units. The
substrate default is no `CapAdd`; do not confuse that with Docker's separate default
capability set when interpreting `capsh` output.

### Make seccomp a positive, versioned policy

The real-substrate tests record that Docker's default seccomp profile admits the
current systemd bases. Keep the override absent and prove the effective filter
is enabled. If a new declared unit has a measured, reproducible syscall
denial, ship one complete checked-in profile derived from a *pinned*
Moby default-profile revision, with only the measured allowance added. Its
source revision, digest, and the reason for every delta belong beside the
profile and its test. It is a code-owned substrate asset, never an SDL field,
`aptl.json` path, environment value, or pack-supplied file.

Do not manufacture a partial “overlay” profile: Docker does not offer a stable
composition contract for such a profile. Do not vendor `main`, copy an
unversioned daemon profile, allow all syscalls, or turn seccomp off as a
compatibility fallback. The profile must be available to the same local or
remote daemon context used by the backend; profile-path handling must stay
contained and fixed rather than accepting a caller-controlled host path.

### Make start and observation attest the same posture

The run command alone is not proof. The Docker backend must use its owned
inspect path after creating a generic init container and before materializing
service content. The same posture check must govern reuse. Require well-shaped
`HostConfig`/`Mounts` readback and verify `Privileged` is false,
`CgroupnsMode` is private, `CapAdd` is exactly the declared plus measured
backend grant, the expected `SecurityOpt` contains `writable-cgroups=true` and
no unconfined or unapproved seccomp/AppArmor override, the expected tmpfs
targets are present, and no host bind or undeclared mount/privilege is
accepted. Declared volumes must match source, target, type, and access mode;
an image-declared anonymous volume is a distinct, qualified allowance. Reject
unexpected host PID/IPC/user namespaces, devices, device-cgroup rules, and
capability drops that change the declared service contract. Check the effective
`AppArmorProfile` where the supported daemon provides AppArmor; only understood
daemon-added defaults may vary. A missing or malformed field is an
unknown posture, not an empty safe set. Do not equate an absent `CapAdd` with
absence of Docker's default effective capabilities, or `SecurityOpt` with proof
that the kernel applied seccomp. The live integration proof must additionally
check PID 1's seccomp mode and effective capability mask, and read the actual
namespace-scoped cgroup mount from inside the container; a Docker `Mounts`
entry alone does not describe that runtime-created mount. Reuse the backend's
inspect/observation parser, not a second authority in the live gate.

The current `_realized_container_matches_spec()` runs on the reuse path; the
create path in `_compose_resource_resolution.start_base_container()` records and
starts a container without this posture readback before service materialization.
Its bind/capability helpers also treat some malformed inspect shapes as empty,
and the comparison does not inspect `Privileged`. Closing those gaps is part of
the implementation contract, while keeping owner-verified removal unchanged.
The current gate is called by `start_base_container()`, while
`_ensure_generic_base_images()` may build an image earlier. Move the gate to the
existing pre-mutation orchestration boundary so an unsupported daemon cannot
trigger a generic image build or resource creation first; retain the start-time
guard against direct backend callers.

The idempotent reuse path is equally important: a running same-image container
must not be accepted until it also passes the expected substrate-posture check.
Conversely, posture mismatch must not become permission to force-remove a
same-named container without the existing project-ownership proof; #964's
container-identity boundary remains applicable.

There is one fixed init baseline. `_INIT_CAPABILITY_BASELINE` and
`_INIT_BIND_MOUNT_TARGETS` in `_runtime_concern_excess.py` must be derived from
or mechanically asserted equal to the effective default `InitRequirements`,
not independently maintained lists. The existing drift test must cover both
capabilities and mount targets. The separate
`raes_runtime_orchestration._allowed_mount_targets()` cgroup exception must be
removed or derived from that same policy as well; otherwise Docker-authority
readback still admits an undeclared cgroup bind. The RAES runtime-concern
observer remains responsible for author-declared capabilities and mounts; do
not invent a fake RAES concern for backend-owned init mechanics.

The Samba AD provider and the reference `reverse` service are separate from the
generic-init baseline. Their remaining `SYS_ADMIN` grants have specific measured
necessity records in `tests/test_compose_capability_necessity.py`; #976 owns any
replacement of those product behaviors. Do not remove either grant by assuming
the generic init result applies. Conversely, do not copy either exception into
the generic policy. The generated and compatibility Compose models must not
emit the retired host cgroup or unconfined seccomp recipe. Scenario-required
privileged behavior, including #974's Docker-authority holder, is a separate
admission and outer-containment question under ADR-055/ADR-060; a narrower init
posture is not a grant of host Docker authority.

## Required Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| Auth and daemon authority | No new API/CLI authorization or pack grant is created. The existing lab route still passes `verify_token` and the BFF Host, CSRF, and two-factor session middleware before `orchestrate_lab_start()`; CLI start uses the same orchestration. The deployment backend selects the target daemon; `DockerEndpointBindingMixin` separately guards #974's socket-bound holder. ADR-055/ADR-060 outer containment stays separate from generic init. A raw Docker socket is not made safe by reduced container flags. |
| RAES schema and admission | Keep strict `RuntimeConfiguration` parsing and semantic validation unchanged. `service_manager_units` selects generic init; separately authored `RuntimeCapabilityPolicy` is preserved under #956, then `qualify_runtime_materialization()` and `effective_runtime_contract_issues()` decide and verify whether the selected backend can faithfully realize it. `_ALLOWED_BACKEND_RUN_CAPABILITIES` limits backend-selected provider grants only. No new SDL, DTO, or config field carries substrate privilege. |
| Operator configuration and env binding | `AptlConfig` remains strict (`extra="forbid"`); no posture toggle, seccomp path, or env override is added. Existing `load_dotenv()`/`valid_environment_variable_name()` and the owner-only `--env-file` path bind operator values. Do not move them into `InitRequirements.env`, process argv, logs, or run records. |
| Docker daemon capability | Query `CgroupVersion` then server version through `DockerComposeBackend`/`SSHComposeBackend`'s configured runner, with its selected `DOCKER_HOST`, timeout, and error translation. A cached pass is valid only for the same verified daemon identity; endpoint changes require revalidation. `hostenv.docker_mode()` is not this probe: it is a local composition fact and would inspect the wrong daemon for SSH deployment. |
| Command and asset boundary | Retain list-form `_run()` commands, fixed code-owned options, project scoping, and bounded timeouts. A custom seccomp profile, if evidence requires one, is a checked-in trusted asset with contained resolution; neither a scenario nor an operator string selects a profile or host path. No secret is introduced into argv or an error envelope. |
| Effective Compose model | `docker-compose.yml` is a compatibility/reference input only where the admitted project-tree path actually applies; env-pack execution uses the generated effective model. Audit the source that actually creates each default container, not merely the checked-in Compose file. Existing effective-model validation remains the owner of Compose `cap_add`/`security_opt` shape. |
| Runtime readback and persistence | Reuse the owned `container_inspect()` path, `_compose_resource_ownership` native-ID receipts, `raes_runtime_observation`, `_runtime_concern_excess`, `_runtime_mount_observation`, and runtime-orchestration mount admission. The init baseline subtracts only the exact code-owned footprint. Missing, substituted, or extra author-declared capability/mount facts fail the RAES closed-world comparison; a posture mismatch never authorizes removal without the existing ownership proof. Persist bounded outcome and identity, never raw inspect JSON or host mount paths. |
| Service realization | Reuse `raes_materializer`'s enable/start operations and `raes_docker_materializer`'s `systemctl is-enabled`/`is-active` read-after-write checks. Container running, a successful `docker create`, or a port opening does not prove a declared unit is active. |
| Errors, logging, and evidence | Expected unsupported-daemon and posture failures travel through `BackendSeedError`, `ApplyResult`/`LabResult`, `StartupDiagnostic`, and the live gate's existing backend-instantiation category. Use `get_logger()` and `redact()`; report a stable posture/cgroup reason and node address, never raw inspect payloads, daemon stderr, full seccomp JSON, environment, host paths, or commands. |
| Fresh boot and live proof | Reuse the now-present #951 `clean-install-lab-boot` wheel/public-start/teardown gate, `assert_boot_realization.py`, `assert_project_teardown.py`, and the full `techvault_live_gate` for the post-#974 clean range. The generic CI fixture proves one Debian service and lifecycle path, not a full range or every base image. Run the supported local Docker Engine v2 proof; #1120 owns qualification claims for alternative runtimes. Preserve prior real-substrate records and the live gate's redacted evidence boundary. |

## Canonical Incumbents And Seam

- `raes_base_substrate.InitRequirements`, `base_container_spec()`, and
  `_ALLOWED_BACKEND_RUN_CAPABILITIES` own generic-init selection and the narrow
  backend provider grant. RAES owns authored capability meaning; #956's
  materialization qualification and readback preserve valid authored intent.
- `_compose_substrate_gate.require_substrate_daemon_support()`,
  `_compose_generic_base_images`, `_compose_base_substrate._init_run_flags()`,
  `_compose_resource_resolution.start_base_container()`, the owned
  `container_inspect()` path, and backend `_run()`/`_subprocess_kwargs()` own
  daemon qualification, image build, start, remote context, and attestation.
- `AptlConfig`, RAES `RuntimeConfiguration`, `runtime_materialization`,
  `_runtime_materialization_effective`, and `DockerEndpointBindingMixin`
  retain their existing configuration, authored-runtime, effective-model, and
  daemon-endpoint boundaries; do not mirror them in a substrate schema.
- `_runtime_concern_excess`, `raes_runtime_observation`,
  `_runtime_mount_observation`, and `raes_runtime_orchestration` own exact
  closed-world readback and its baseline exceptions.
- `_compose_resource_ownership` and `_compose_resource_resolution` own native-ID
  receipts and safe reuse/removal; `raes_materializer`,
  `raes_docker_materializer`, `tests/test_substrate_posture_real_docker.py`,
  `tests/test_compose_capability_necessity.py`, the clean-install gate, and the
  full live validation gate own service and range proof.

The repository surface is the selected systemd Dockerfiles under
`containers/generic-systemd*`, generated realization in `src/aptl/backends`
and `src/aptl/core/deployment`, applicable `docker-compose*.yml`, strict
`src/aptl/core/config.py`, API/CLI startup, the local or selected remote Docker
daemon and Linux cgroup/LSM behavior, and the proof and cleanup owners in
`.github/workflows/checks.yml`, `scripts/ci/`, and `docs/raes/`. Apply the
focused-test and fresh-lab conventions in `.gc/plan-rules.md`; no parallel
configuration or validation path is needed.

The narrow extensibility seam is the backend-private, daemon-derived support
probe plus the one code-owned `InitRequirements` posture and shared attestation.
A future supported runtime or cgroup-v1 implementation must be an explicit,
separately qualified backend policy with its own exact readback baseline; it
must not be a scenario flag or a boolean that silently re-enables host
authority. A future systemd syscall requirement changes the pinned profile's
documented delta and the same shared attestation, not every scenario or a new
RAES schema. #1120 owns alternative-runtime qualification.

## Proof Obligations And Boundaries

The implementation must prove, on the supported local Docker Engine v2 runtime,
the Debian and RHEL generic systemd bases, any selected layered variants, and
the post-#974 clean range:

- `Privileged` is false, `CgroupnsMode` is exactly private, no host cgroup bind
  or undeclared mount appears, the actual cgroup2 mount is namespace-scoped and
  writable, no inspected security option is unconfined, and PID 1 has seccomp
  filtering enabled. Negative controls must show stale privileged containers
  fail reuse, while owner conflicts are never deleted by name.
- `CapAdd` equals declared plus separately measured backend additions; PID 1's
  effective mask and `capsh` distinguish those additions from Docker defaults.
  Service startup and negative-control evidence justify every retained grant;
  a `systemd-analyze security` score alone does not establish necessity.
- every declared `service_manager_unit` is enabled/active where its SDL state
  requires it, including the existing real-Docker service and DNS coverage;
  failures are not waived because a container is running.
- the baseline drift tests, excess-detection tests, runtime-orchestration mount
  admission tests, wheel-installed clean boot/teardown, and the public full
  live gate pass for the post-#974 range. A skipped real-Docker test, a cached
  developer image, a running container, or the small CI fixture alone is not
  the outstanding clean-range proof. Retain the prior real-substrate
  measurements as historical evidence rather than overwriting them.

Non-goals: adding a generic privilege configuration surface, changing RAES
runtime schemas or #956's fidelity contract, introducing an authored-capability
allowlist or silently narrowing valid SDL, removing #976's measured Samba/Falco
grants, qualifying alternative runtimes (#1120), supporting cgroup v1,
redesigning Docker/SSH backends, authoring #1129's operator-grant policy, or
treating `docker-compose.yml` as an env-pack authority. Avoid a per-scenario
exception, an unversioned or permissive seccomp profile, raw Docker calls in
validators/CLI, a second exception or result hierarchy, duplicating the
baseline, trusting missing inspect fields as empty, and using live validation
as a substitute for startup-time enforcement.
