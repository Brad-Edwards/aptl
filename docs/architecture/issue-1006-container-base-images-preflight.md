# Issue #1006 Container Base-Image Migration Preflight

This note fixes the architectural boundaries for issue #1006. It is guidance,
not an implementation plan. The migration changes supply chain inputs and the
OS/runtime substrate; it must not weaken the existing realization, security, or
deployment contracts.

## Decisions and guardrails

1. **Keep two different digest contracts distinct.** Every registry `FROM`
   remains `tag@sha256:<digest>`, as enforced by
   `tests/test_supply_chain_pinning.py` and refreshed by the Docker entries in
   `.github/dependabot.yml`. Separately, an env-pack
   `materialization_specification.digest` is the SHA-256 of the *Dockerfile
   bytes*. It authorizes an APTL-owned component build, not an OCI base image.
   Updating either value manually, treating one as a substitute for the other,
   or relaxing the policy makes the result untrusted. Update the byte digests
   only through the env-pack release that authors them, then update
   `raes-env-packs` and its lock/export artifacts together.

2. **The external pack no longer pins any APTL Dockerfile.** This guardrail
   originally said `containers/ad/Dockerfile`,
   `containers/wazuh-sidecar/Dockerfile` and
   `containers/kali-ssh-proxy/Dockerfile` had to stay byte-identical until
   OpenRAE/env-packs#347 shipped matching specifications. #347 shipped by
   *removing* the pins: TechVault 6.0.1 declares 29 nodes and no `source` on
   any of them, so there is no `materialization_specification`, no
   `aptl-contained-component-build` profile, and no Dockerfile byte digest left
   in the pack. Every Dockerfile here is APTL-owned and free to change.

   The mechanism the guardrail protected still exists and still fails closed:
   `raes_artifact_availability._materialized_specifications` hashes the exact
   Dockerfile and builds only an exact match, and the image policy rejects
   anything else with `aptl.provisioner.image-policy-rejected`. If a future
   pack authors a component build again, do not add an APTL exception, bypass
   availability, patch generated realization output, or use a local image tag
   to work around a rejected source. Update the pack release instead.

3. **Make SSH policy explicit at the OpenSSH include boundary.** Ubuntu 26.04
   uses `sshd_config.d` drop-ins. Both duplicated shared-base layers
   (`containers/base/Dockerfile.ubuntu` and `containers/reverse/Dockerfile`)
   must install one root-owned, non-writable APTL drop-in in the directory the
   distro configuration includes, with deterministic lexical precedence, rather
   than editing distribution-owned `/etc/ssh/sshd_config`. It must preserve the
   present effective policy: root login disabled, password authentication
   disabled, public-key authentication enabled. Verify the effective daemon
   configuration with `sshd -t` and `sshd -T`; file text or a successful image
   build is insufficient. Keep `AcceptEnv` and `Match User kali` ownership in
   the Kali-specific image/configuration path--do not copy those settings into
   this generic Ubuntu substrate.

4. **Preserve image ownership and realization routing.**
   `containers/generic-systemd-base-debian/Dockerfile` produces the local-only
   `aptl/generic-systemd-base-debian:latest` selected by
   `raes_materializer._SERVICE_BASE_IMAGE` and built through
   `DockerComposeBackend.ensure_generic_base_image`; its Debian bump must retain
   that tag, build-context map, systemd contract, and fresh-machine behavior.
   `misp-suricata-sync` is an image-free RAES runtime node in the static Compose
   reference file, so its static Compose stub is not its live image authority.
   Do not make Compose a second source of image selection or change the
   scenario-agnostic materializer to special-case a migrated service.

5. **Runtime bumps are compatibility work, not packaging edits.** Python 3.14
   images must retain hash-verified third-party installation from
   `requirements/{runtime,web}.txt`, local `pip install -e . --no-deps`, and
   `--no-build-isolation`; Node 26 must retain `npm ci` and the committed
   lockfile. Do not alter Python project support metadata, dependency ranges,
   locks, application error envelopes, or web authentication merely to make an
   image build. Evidence of a real incompatibility is required for a separate
   compatibility change.

6. **Reuse the established scanner boundary.** The existing `trivy-image`
   matrix in `.github/workflows/checks.yml` builds and scans base-ubuntu,
   reverse, misp-suricata-sync, wazuh-sidecar, web, and web-api. Keep its
   advisory artifact-only posture from ADR-026. If coverage is extended to the
   unscanned Alpine or generic-Debian Dockerfiles, add them to this one matrix;
   do not create another scanner workflow, custom Dockerfile parser, or a
   falsely clean scan of a pulled base rather than the built image.

## Required cross-cutting passage

| Layer | Canonical incumbent and required outcome |
| --- | --- |
| Supply chain | Digest-pinned `FROM`, Dependabot Docker directories, `tests/test_supply_chain_pinning.py`, `uv.lock`, generated hash exports, `npm ci`. New bases retain all pins; an env-pack byte digest is never represented as a `FROM` digest. |
| Pack/admission policy | `artifact_availability_for_scenario`, `_materialized_specifications`, `raes_image_realization`, `_raes_image_policy`, and `tests/test_env_pack_realization.py`. The new pack release must admit all affected component sources; a mismatch remains fail-closed and secret-free. |
| Config/schema/validation | RAES `ArtifactRequirement.materialization_specifications` is the only schema for component-build authorization. Existing Docker/Compose build contexts and the `_SERVICE_BASE_IMAGE`/`_GENERIC_BASE_BUILD_CONTEXTS` maps remain canonical; no migration flag, duplicate image manifest, or local exception schema. |
| OS exposure | Existing Compose ports, profiles, volumes, capabilities, health checks, and loopback-only web API/UI bindings remain unchanged unless separately justified. The SSH drop-in narrows daemon authentication policy and must not create a new listener, credential input, or shell interpolation surface. |
| Secrets and errors | `web/Dockerfile.api` continues to mint/session-handle secrets via `aptl web serve` and ADR-039; token values do not enter the UI image. Pack rejection continues through the existing redacting diagnostic code; do not expose Dockerfile bytes, local paths, build output, or environment values in a new error envelope. |
| Observability/persistence | No new runtime record, logging channel, or database schema is warranted. CI SARIF artifacts and existing container logs are the evidence surfaces; do not persist scanner output or build metadata in lab state. |
| Deployment/host runtime | Compose and generated RAES realization both see the affected assets. Generic systemd bases require a clean local Docker build/boot with the current cgroup, tmpfs, capability, and seccomp contract; generated `.aptl/realization` is evidence only. |

## Extensibility seam

The seam for future base refreshes is the existing combination of a mutable
human-readable tag plus immutable registry digest, with Dependabot responsible
for proposing refreshes. For component builds, the upstream
`materialization_specifications` release is the corresponding seam. Do not add
per-image migration switches or an APTL-maintained second digest catalogue.

The one necessary OS-level seam is an APTL-owned SSH drop-in, shared by the two
Ubuntu layers, rather than a version-specific `sed` mutation of a vendor file.
It permits future Ubuntu OpenSSH layout changes while keeping the effective
three-directive policy testable. It is not a general SSH configuration framework.

## Verification boundaries and non-goals

- Validate every changed Dockerfile with its declared build context, then run
  `sshd -t` and `sshd -T` in both Ubuntu-derived images; test the actual
  systemd substrate via the existing clean-machine/generic-base path.
- Run the focused env-pack realization/admission tests with the new pack, the
  Python service tests for `misp-suricata-sync`, `reverse`, and web API, the
  web lockfile build/test path, repository `pytest`, and
  `pre-commit run --all-files`. Review the existing Trivy image SARIF results;
  advisory status is not permission to ignore newly actionable findings.
- Do not change Dependabot grouping/policy, RAES schemas or image-policy
  behavior, Compose topology, port exposure, privileges, health/readiness
  ownership, application DTOs/errors/logging, or the generic materializer.
- Do not solve an Ubuntu packaging change with `|| true`, an empty/inactive
  SSH configuration file, in-place edits to a vendor config, a shell-based
  config generator, a global OpenSSH relaxation, a cached-image-only result,
  or a test that merely greps source text.
