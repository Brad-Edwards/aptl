# Issue #677 Certificate Producer Ownership Preflight

This note fixes the architecture guardrails for making Wazuh certificate
generation host-user-owned from creation. It is design guidance, not an
implementation plan. ADR-007 remains authoritative for the Python lab control
plane, ADR-029 for secret handling, ADR-031 for startup results and ordering,
ADR-034 for certificate boundaries, ADR-037 for Docker execution, and ADR-043
for the broader rule that a producer must not mutate host-source ownership.

No new ADR is needed. This issue removes an unsafe implementation detail while
preserving those accepted boundaries.

## Architecture Decisions

- Keep `aptl.core.certs.ensure_ssl_certs()` as the single owner of legacy Wazuh
  certificate generation. On native Linux Docker, the generator process must
  run under the invoking host UID/GID and the bind source must be created by
  the host user before Compose runs. Generated ownership is a producer
  invariant, not a cleanup concern.
- Reuse `aptl.core.hostenv.needs_host_ownership_fix()` as the only gate for
  native-Linux ownership semantics. Resolve `os.getuid()` and `os.getgid()`
  only inside that true branch. Docker Desktop, other Docker VMs, Windows, an
  unavailable engine, and an unknown engine must not evaluate either POSIX API
  or receive a numeric user override.
- Remove the post-generation ownership-repair operation completely. A root
  helper container is still post-hoc `chown`; replacing host `sudo` with Docker
  root does not satisfy the producer-ownership boundary. Do not retain a
  dormant repair command or fallback to it when user-mode generation fails.
- Keep ownership and permission modes distinct. `_ensure_container_readable_certs()`
  remains the canonical host/container readability contract: an owner-only
  `0700` directory protects the bundle while `0644` PEM files remain readable
  by non-root Wazuh consumers whose container UID may differ from the host UID.
  A non-privileged `chmod` by the owning host user is not ownership repair and
  must not be replaced with `chown` or indiscriminately gated off Docker
  Desktop.
- Preserve the isolated Compose project name, generator timeout, unconditional
  `down --remove-orphans` cleanup, manager-root-CA alias, and fail-closed
  `CertResult` outcome. Ownership must not be fixed by rejoining the generator
  to the lab networks or skipping cleanup of its temporary network.
- Preserve the injected `run_command` seam used by typed stateful realization.
  Do not add a generic Docker passthrough, a second generator service, a new
  result DTO, or a certificate-specific exception hierarchy.

## Compatibility Constraint

Repository history matters here. The first host-user implementation was later
replaced because the pinned `wazuh/wazuh-certs-generator:0.0.2` image's default
entrypoint did not execute successfully as an arbitrary host UID. The current
root-plus-repair behavior documents that constraint in `certs.py`.

Consequently, adding `--user` to the command is necessary but not sufficient.
The generator invocation must prove that the pinned image's real certificate
workflow completes under that identity. If its entrypoint mode requires an
interpreter/entrypoint override, keep that override narrow, fixed to trusted
image-internal paths, and in the same Compose run. It must not bypass the Wazuh
certificate workflow, interpolate project data into shell text, restore root
execution, or add a repair phase. An image incompatibility is a blocking
producer-boundary problem, not permission to fall back silently.

Keep the image reference canonical in `generate-indexer-certs.yml`. An image
upgrade or locally maintained replacement has supply chain and certificate
compatibility consequences and is outside this issue unless separately
authorized.

The producer fix governs newly generated bundles. A checkout that already has
a foreign-owned historical bundle is migration debt: the existing-bundle
no-op cannot make it host-manageable without a separate rotation, retirement,
or privileged-recovery decision. Do not hide that state behind a successful
no-op, silently rotate trusted material, or reintroduce a repair container. If
the acceptance contract is intended to cover upgrades with pre-existing
root-owned bundles, that migration requires explicit scope before coding.

## Cross-Cutting Layers and Canonical Incumbents

| Layer | Existing owner and required behavior |
|---|---|
| Host/runtime classification | `aptl.core.hostenv.docker_mode()` and `needs_host_ownership_fix()` distinguish native Linux from Docker Desktop/VM/unknown modes. Do not duplicate `sys.platform`, Docker-info parsing, WSL detection, or OS-name branches in `certs.py`. |
| Certificate orchestration | `aptl.core.certs.ensure_ssl_certs()`, `_cert_generator_command()`, `_execute_command()`, `_cert_generator_project_name()`, and `_cleanup_cert_generator()` own generation, backend-runner injection, project isolation, timeouts, and cleanup. |
| Generator inputs | `generate-indexer-certs.yml` owns the generator image/service and bind mounts; `config/certs.yml` owns Wazuh certificate subjects and addresses. Add no `PUID`/`PGID` environment convention, duplicate Compose file, or second certificate schema. |
| Startup workflow | `aptl.core.lab._step_generate_certs()` and `_LAB_START_STEPS` own ordering and fatal conversion to `LabResult`. Generation remains before bind-mount validation and container startup. |
| Generated-artifact validation | `ComposeStatefulRealizationMixin`, `stateful_realization_errors()`, `_canonical_generated_path()`, and `validate_certificate_bundle()` own remote-artifact refusal, output/path shape checks, no-symlink containment, declared-output presence, chain/key/SAN checks, and permission checks. The ownership change must pass these gates rather than duplicate them in the command builder. |
| Bind consumers | `docker-compose.yml` is the canonical Wazuh manager/indexer/dashboard read-only mount topology. The generator UID does not change the runtime users or mount destinations of those services. |
| Secret storage and packaging | `.gitignore`, `aptl._asset_manifest.EXCLUDED_DIR_NAMES`, `hatch_build.py`, and the asset tests keep generated Wazuh and SOC key material out of Git, wheels, and initialized source bundles. |
| Results and observability | `CertResult`, `LabResult`, `LabActionResponse`, `get_logger()`, and ADR-029 are the existing error/log surfaces. Failures may name the generation or cleanup layer, but must not include PEM/key bytes, secrets, or a full command line. |
| Tests and workflow | `tests/test_certs.py`, `tests/test_hostenv.py`, `tests/test_lab.py`, `tests/test_deployment_stateful_realization.py`, `tests/test_no_silent_privilege_escalation.py`, asset/build-hook tests, `pytest`, and `pre-commit run --all-files` are the canonical gates. A clean native-Linux lab boot is the required product proof. |

The SOC certificate generator in `aptl.core.soc_ca` is deliberately separate:
it generates `config/soc_certs/` in-process as the host user and already owns
its registry, atomic writes, containment, key modes, and secret-safe error
envelope. Do not merge the Wazuh and SOC generators or their `CertResult`
classes as part of this issue. SOC bring-up is a regression surface, not a
second ownership implementation target.

## Security and Validation Layers

- **Authentication surface:** this change adds no request or command option.
  API-triggered starts remain behind the existing `verify_token` router
  dependency; CLI starts remain local operator actions. UID/GID must be derived
  locally, never accepted from an API body, CLI flag, `aptl.json`, `.env`, or a
  scenario.
- **Environment and config shapes:** no environment variable or strict
  `AptlConfig` shape changes. `config/certs.yml` remains the sole non-secret
  certificate provenance input, and typed realization continues to accept only
  the existing `certificate_bundle` artifact/output schema.
- **Generated-path gate:** the typed path must continue through
  `_canonical_generated_path()` before Docker mutation; declared outputs must
  remain safe relative paths and read-only consumers. The legacy generator
  must not weaken that no-symlink/project-root rule when pre-creating or
  changing modes on the output directory.
- **Certificate validator:** declared bundles continue through
  `validate_certificate_bundle()` for file presence, symlink and mode safety,
  root/manager-root consistency, current validity, key pairing, issuer chain,
  and SAN/provenance agreement. User ownership alone is not a valid bundle.
- **Secret handling:** private keys remain under the gitignored generated
  directory. Preserve the `0700` parent and read-only Compose mounts; never log,
  print, archive, package, or return certificate/key contents. UID/GID are not
  secrets, but there is no operator value in logging them.
- **OS/process exposure:** pass Docker arguments as a list. The numeric
  `UID:GID` may appear only as the non-secret value of Compose's `--user`
  argument. Do not invoke `id`, `sudo`, `chown`, a host shell, or a root helper
  container; do not place PEM, key, credential, or environment values in argv.
- **Error envelopes:** preserve subprocess timeout handling and convert failure
  through `CertResult` to fatal `LabResult`/`LabActionResponse`. Any new
  compatibility failure should name a stable layer and exit status, not echo a
  command, host environment, key path inventory, or unredacted upstream body.
- **Persistence and evidence:** no repository/database transaction is involved.
  Stateful realization may persist only its existing non-secret public-root
  fingerprint and validation booleans; ownership metadata and private material
  do not belong in run records or ACES evidence.

## Extensibility Seam

The seam is the existing host-environment decision plus the optional execution
identity consumed by the certificate command builder, with Docker execution
still injectable through `run_command`. The next reasonable host-runtime
variation should change `hostenv` classification or the identity returned by
that boundary once, not add another OS branch or ownership strategy to
certificate orchestration.

The generator image/service/version remains parameterized by the canonical
Compose asset. A future generator-image change should not require copying its
reference into Python, deployment DTOs, docs, or a repair command.

## Whole-Repository Surface

- Certificate producer and platform boundary: `src/aptl/core/certs.py` and
  `src/aptl/core/hostenv.py`.
- Startup and deployment boundary: `src/aptl/core/lab.py` and
  `src/aptl/core/deployment/_compose_stateful_{constants,graph,realization}.py`.
- Certificate validation: `src/aptl/core/deployment/_stateful_certificates.py`.
- Canonical assets and consumers: `generate-indexer-certs.yml`,
  `config/certs.yml`, and the Wazuh mounts in `docker-compose.yml`.
- Adjacent SOC regression boundary: `src/aptl/core/soc_ca.py`,
  `src/aptl/core/_soc_ca_io.py`, and the `config/soc_certs/` mounts.
- Distribution and secret exclusion: `.gitignore`,
  `src/aptl/_asset_manifest.py`, `hatch_build.py`, and their tests.
- Operator guidance: `docs/getting-started/installation.md`,
  `docs/deployment.md`, and `docs/troubleshooting/index.md`. Manual raw Compose
  certificate commands bypass the platform-aware identity policy and must not
  remain the recommended regeneration path.
- Verification: certificate, host-environment, startup, stateful-realization,
  privilege-escalation, asset, and package-build tests plus native Linux and
  Docker Desktop lab-start evidence.

## Gotchas and Anti-Patterns

- Do not conflate host file owner, generator process user, and the fixed
  non-root UIDs used later by Wazuh services. `--user <host UID>:<host GID>`
  applies only to the one-shot producer.
- Do not conflate UID/GID ownership with `0700`/`0644` mode policy. Removing
  the readability pass can make correctly owned certs unusable by Wazuh.
- Pre-create the native-Linux bind source as the host user. Otherwise Docker
  may create the missing host directory as root before container `--user`
  takes effect.
- Do not call `os.getuid()`/`os.getgid()` before the platform gate, including
  while computing defaults, formatting log arguments, or constructing test
  fixtures. Those attributes are absent on native Windows Python.
- Do not use a mocked Docker Desktop unit path as proof of host ownership. The
  file-sharing result is a runtime contract and needs live Desktop evidence;
  the unit test proves only command construction and absent POSIX calls.
- Do not treat Linux host, Linux Docker Desktop, WSL2, Colima/Lima, and native
  Linux Docker as interchangeable. The repository's Docker-mode probe is the
  policy boundary.
- Do not restore host `sudo`, Docker-root `chown`, a root entrypoint phase, or a
  best-effort fallback. Generation failure must stop startup.
- Do not remove isolated-project cleanup while changing command ordering; a
  leaked generator network can overlap the TechVault networks.
- Do not update only the legacy `_step_generate_certs()` path. Typed ACES
  realization calls the same generator with an injected backend runner and
  then applies stronger output validation.
- Do not leave documentation telling operators to regenerate with raw
  `docker compose -f generate-indexer-certs.yml run ...`; that bypasses the
  platform policy and can recreate the root-owned state.
- Do not treat the repository-wide `sudo -n` AST guard as the complete
  acceptance test. The certificate path must separately prove that it issues
  no `sudo`, `chown`, root helper, or repair command at all.
- Do not broaden this issue into Wazuh certificate rotation, CA redesign,
  service UID remapping, generalized host-file repair, or deployment-backend
  redesign.

## Non-Goals and Boundaries

This issue does not change certificate subjects/SANs, Wazuh TLS topology,
private-key distribution, Wazuh service runtime users, SOC CA generation,
Compose profiles, remote generated-artifact support, ACES schemas, durable
configuration, environment variables, API/web contracts, startup readiness
taxonomy, run-record schemas, or certificate rotation. It does not upgrade the
generator image, introduce a custom image, or add a generic ownership manager
without separate authorization and supply chain review.
