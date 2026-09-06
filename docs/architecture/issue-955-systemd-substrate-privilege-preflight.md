# Issue #955 Generic Systemd Substrate Privilege Preflight

This note fixes the design boundary for reducing the generic systemd substrate's
host authority. It is guidance, not an implementation plan. No ADR is needed:
ADR-048 already assigns generic substrate selection and realization to the
backend, and ADR-046 already requires bidirectional runtime parity.

## Architecture Decisions

### Keep init intent separate from container-security mechanism

`runtime.service_manager_units` is the sole RAES signal that a generic node
needs systemd. It is not an authorization for an author to select a cgroup
namespace, mount a host cgroup filesystem, disable seccomp, or add a
capability. `InitRequirements` remains the code-owned, scenario-independent
translation of that intent; `runtime.linux_capabilities` remains subject to
`_ALLOWED_EXTRA_CAPABILITIES` and continues to reject `CAP_SYS_ADMIN`.

The supported generic-systemd substrate is cgroup v2 only. Before any generic
systemd image build, network creation, or container removal, the selected
deployment backend must query the *target Docker daemon's* cgroup version using
its existing argv-list runner. It must fail closed with one bounded
`LabResult`/`BackendSeedError` diagnostic when the result is not v2, including a
failed or unparseable query. Do not retain a cgroup-v1 compatibility branch in
this issue: it would create a host-dependent privilege baseline and a second
readback policy. Docker documents private cgroup namespaces as the v2 default
and host namespaces as the v1 default; the backend must nevertheless request
`--cgroupns=private` explicitly so the inspected contract is deterministic.

`InitRequirements` must therefore describe one v2 posture: private cgroup
namespace, no `/sys/fs/cgroup` bind mount, existing private `/run`,
`/run/lock`, and `/tmp` tmpfs needs, and no blanket added capabilities. An
added capability may return only as a documented, per-substrate necessity
proved for both generic base images and the affected declared units. The
default is no `CapAdd`; do not confuse that with Docker's separate default
capability set when interpreting `capsh` output.

### Make seccomp a positive, versioned policy

First qualify the Docker default seccomp profile with the v2 substrate. If it
admits the systemd and declared-unit syscall surface, omit the seccomp override
and prove the effective filter is enabled. If a measured, reproducible syscall
denial remains, ship one complete checked-in profile derived from a *pinned*
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

The run command alone is not proof. The Docker backend must use daemon-owned
`container_inspect()` after creating a generic init container and before
materializing service content to corroborate the expected namespace mode,
absence of the host cgroup bind, exact extra-capability set, and absence of an
unconfined seccomp option. The full live gate must reuse that same backend
attestation/parser rather than add a second `docker inspect`/shell parser. Its
integration evidence must additionally demonstrate a nonzero seccomp mode for
PID 1, while recognizing that a test-only in-container read is liveness
evidence, not the authority for configuration attestation.

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

The Compose-managed AD controller is outside the generic-init baseline but is
inside the issue's `CAP_SYS_ADMIN` acceptance criterion. Its current direct
`cap_add: SYS_ADMIN` must be independently removed or documented with a
reproducible necessity test. The legacy/reference reverse service has the old
systemd recipe too. Do not copy it into the generic policy, and do not claim
the default range is hardened while an applicable generated or compatibility
Compose model still emits `seccomp:unconfined`, a host cgroup mode, or an
undocumented `SYS_ADMIN` grant.

## Required Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| RAES schema and admission | Keep strict `RuntimeConfiguration` parsing and semantic validation unchanged. `service_manager_units` selects generic init; `RuntimeCapabilityPolicy` still passes `_ALLOWED_EXTRA_CAPABILITIES`, which rejects author-supplied `CAP_SYS_ADMIN`. No new SDL, DTO, or config field carries substrate privilege. |
| Docker daemon capability | Query `CgroupVersion` through `DockerComposeBackend`/`SSHComposeBackend`'s configured runner, with its remote `DOCKER_HOST`, timeout, and error translation. `hostenv.docker_mode()` is not this probe: it is a local composition fact and would inspect the wrong daemon for SSH deployment. |
| Command and asset boundary | Retain list-form `_run()` commands, fixed code-owned options, project scoping, and bounded timeouts. A custom seccomp profile, if evidence requires one, is a checked-in trusted asset with contained resolution; neither a scenario nor an operator string selects a profile or host path. No secret is introduced into argv. |
| Effective Compose model | `docker-compose.yml` is a compatibility/reference input only where the admitted project-tree path actually applies; env-pack execution uses the generated effective model. Audit the source that actually creates each default container, not merely the checked-in Compose file. Its existing model validation remains the owner of Compose `cap_add`/`security_opt` shape. |
| Runtime readback | Reuse `container_inspect()`, `raes_runtime_observation`, `_runtime_concern_excess`, `_runtime_mount_observation`, and runtime-orchestration mount admission. The init baseline subtracts only the exact code-owned footprint. Missing, substituted, or extra author-declared capability/mount facts continue to fail the RAES closed-world comparison. |
| Service realization | Reuse `raes_materializer`'s enable/start operations and `raes_docker_materializer`'s `systemctl is-enabled`/`is-active` read-after-write checks. Container running, a successful `docker create`, or a port opening does not prove a declared unit is active. |
| Errors, logging, and evidence | Expected unsupported-daemon and posture failures travel through `BackendSeedError`, `ApplyResult`/`LabResult`, `StartupDiagnostic`, and the live gate's existing backend-instantiation category. Use `get_logger()` and `redact()`; report a stable posture/cgroup reason and node address, never raw inspect payloads, daemon stderr, full seccomp JSON, environment, host paths, or commands. |
| Fresh boot and live proof | Reuse #951's fresh-directory/public-start harness and `techvault_live_gate`, not an ad-hoc Docker script as the acceptance authority. The harness must cover native Linux Docker and Docker Desktop v2 daemons, clean up only the validated project, and preserve the live gate's redacted evidence boundary. |

## Canonical Incumbents And Seam

- `raes_base_substrate.InitRequirements`, `base_container_spec()`, and
  `_ALLOWED_EXTRA_CAPABILITIES` own generic-init selection and the capability
  policy.
- `_compose_base_substrate._init_run_flags()`, `start_base_container()`,
  `container_inspect()`, and the backend `_run()`/`_subprocess_kwargs()` path
  own daemon invocation, remote context, timeout, and immediate attestation.
- `_runtime_concern_excess`, `raes_runtime_observation`,
  `_runtime_mount_observation`, and `raes_runtime_orchestration` own exact
  closed-world readback and its baseline exceptions.
- `raes_materializer`, `raes_docker_materializer`, the image-free integration
  tests, the fresh-start gate, and the live validation gate own service and
  range proof.

The narrow extensibility seam is the backend-private, daemon-derived cgroup
capability probe plus the one code-owned `InitRequirements` posture. A future
supported cgroup-v1 implementation must be an explicit, separately qualified
backend policy with its own exact readback baseline; it must not be a scenario
flag or a boolean that silently re-enables host authority. A future systemd
syscall requirement changes the pinned profile's documented delta and the same
shared attestation, not every scenario or a new RAES schema.

## Proof Obligations And Boundaries

The implementation must prove, for Debian and RHEL generic systemd bases and
for the default range on both required v2 daemon environments:

- `CgroupnsMode` is exactly private; no inspected bind target is
  `/sys/fs/cgroup`; no inspected security option is unconfined; and PID 1 has
  seccomp filtering enabled.
- `CapAdd` equals the code-owned init requirement; `capsh` distinguishes those
  additions from Docker defaults; `systemd-analyze security` and service
  startup evidence justify every retained capability.
- every declared `service_manager_unit` is enabled/active where its SDL state
  requires it, including the existing real-Docker service and DNS coverage;
  failures are not waived because a container is running.
- the baseline drift tests, excess-detection tests, runtime-orchestration mount
  admission tests, fresh-directory boot, and public live gate all pass. The
  fresh proof is blocked on #951's harness landing; do not replace it with a
  developer-cache or already-running-range result.

Non-goals: adding a generic privilege configuration surface, changing RAES
runtime schemas, widening the capability allowlist, supporting cgroup v1 in
this change, redesigning Docker/SSH backends, or treating `docker-compose.yml`
as an env-pack authority. Avoid a per-scenario exception, an unversioned or
permissive seccomp profile, raw Docker calls in validators/CLI, a second
exception or result hierarchy, duplicating the baseline in three places, and
using live validation as a substitute for startup-time enforcement.
