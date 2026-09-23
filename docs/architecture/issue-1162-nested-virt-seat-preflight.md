# Issue #1162: Nested Virt Seat Preflight

Architecture guidance for [#1162](https://github.com/Brad-Edwards/aptl/issues/1162),
whose supplied issue body is the delivery contract; no Ground Control requirement
is attached. This is not an implementation plan or a working-VM attestation.
Inspection used repository commit `0bdd55b87f59` and cached remote-tracking refs.

## Owner decision after preflight

The owner selected **GHCR plus Cosign verification**, retaining local builds
and manual VM proof, and authorized updating the ADR to describe this
replacement. Reuse the existing GHCR seat work, including local commit
`20800117436a`, while replacing its digest-only admission with trusted Cosign
verification. This supersedes the recommendations below to retain the custom
signed-release transport and not import that branch. Artifact authentication,
offline verified reuse, safe replacement, real VM evidence and physical-host
containment remain required. Image cuts are independent of package releases.

The donor diff was applied as ordinary working-tree edits after the local
command hook rejected a branch merge. Neither the donor branch nor PR #1161
was changed. The implementation contract is now ADR-060 and the updated seat
launcher reference; the remaining preflight text records the initial assessment,
including interfaces subsequently replaced by the approved design.

Keep [ADR-060's VM-only containment](../adrs/adr-060-vm-only-seat-containment.md),
[ADR-049's disposable, verified release](../adrs/adr-049-sealed-disposable-lab-appliance.md),
and [ADR-059's full-TechVault and host-access boundaries](../adrs/adr-059-canonical-techvault-delivery-and-host-mcp-access.md).
The issue changes the image delivery cadence and user consent contract. It does
not waive signing, qualification, or physical-host/cross-seat protection. No new
platform abstraction or ADR is needed; this note replaces the package-release
coupling prescribed by the older #1022 preflight for this issue only.

## Historical preflight findings (superseded where noted)

| Observed incumbent | Consequence for #1162 |
| --- | --- |
| `cli/seat.py` requires a tag and two public anchors for installation, downloads without confirmation, and has no image-update command. `public_install.py` only reuses an identical installed release or refuses replacement. | Add consent and source selection through the existing CLI/install boundary; do not treat installation as an existing updater. |
| `public_install.py` fetches complete signed releases from GitHub Release assets. `publish-images.sh` publishes guest container inputs to GHCR. | A published container input is not the requested VM. GHCR must carry the complete verified appliance, with the disk, offline payload, metadata and evidence bound together. |
| `ReleaseSource.validate_tag()` requires `source_tag == v<aptl_version>`; local builds use `CandidateSource` and cannot enter the current production seal path. | Removing workflow jobs alone cannot deliver independent local image cuts. Evolve the canonical source contract, preserving exact commit identity and qualification. |
| Release Please runs build, qualification, sealing, publication and public acceptance; even `backmerge.needs` depends on appliance acceptance. | Remove image-cut dependencies from the package release graph, including transitive dependencies and corresponding workflow tests. Keep ordinary package publication and provenance. |
| `guest_surfaces.py` serves fixed participant HTML and coarse recovery JSON. | A mapped HTTP 200 is not proof of the real workbench, range, SOC or MCP behavior. |
| `build.py` sanitizes `/var/lib/aptl/*`, but `provision-offline.sh` creates `/var/lib/aptl/mcp` and `scan-golden.sh` requires that empty directory. | Reconcile sanitization with immutable service-account scaffolding; keep overlay state absent without deleting required installed structure. This is a source-level contract conflict, not a reproduced VM failure. |
| Cached `origin/seat-image-from-ghcr` at `65c92d5a` contains related web boot/network fixes but also deletes signed release, payload and qualification owners. | Inspect individual changes as donor evidence. Do not transplant the branch wholesale or silently adopt its weaker contracts. |

The available history did not establish which revision was manually working
around August 6. Record the exact donor SHA and its demonstrated behavior before
claiming restoration; branch names and timestamps alone are insufficient.

## Image Selection, Consent And Replacement

Keep `aptl seat` as the operator interface and `aptl appliance` plus the existing
scripts as the image engineering interface. A fresh installed CLI must support
default seat acquisition without a source checkout. Downloads belong to an
explicit seat invocation, never a wheel install hook, import, help, or status
command. If `seat start` provides first-use acquisition, it calls the same
selection/install operation as `seat install`.

Resolve explicit CLI selection before configured selection, then the repository's
default public GHCR channel. Configuration and an installed selection are
different facts: a mutable channel is resolved once to an immutable digest;
subsequent starts use the selected verified local release.
An update must not silently turn a digest pin into a mutable channel; changing
that coordinate requires an explicit source choice.

| State | Required behavior |
| --- | --- |
| Valid local release for the selected source | Reuse it without default-channel lookup or download, including when offline. |
| No local release and no alternate source | Offer the default public image; after consent resolve its current qualified channel target and install it. |
| Explicit/configured alternate source | Honor only that source. A remote alternate uses the same consent and verification gates; a missing local alternate fails. Never fall back to the public default. |
| Present invalid config, corrupt/incompatible local release, or incomplete prior transaction | Report the specific bounded failure or recover the owned transaction. Do not reinterpret it as absence and silently download or destroy state. |
| Explicit image update | Confirm replacement through `aptl seat`; resolve and verify the new selection, replace safely, and remove superseded owned bytes when no retained overlay references them. |

Follow `cli/lab.py`'s default-no Typer confirmation and `--yes`/`-y` convention,
with prompts at the CLI boundary. Non-interactive input, EOF and refusal cannot
authorize a download or deletion. Prompt before network acquisition, including
metadata; explain source and replacement impact, and report verified size and
identity when available. Keep prompts/progress on stderr so stdout remains the
seat JSON contract. Auto-approval bypasses consent only, never validation,
signature checks, ownership, capacity admission or qualification.

Updates are transactions over an immutable base and disposable overlay, not
in-place VM upgrades. Reuse `seat_mutation_lock`, lifecycle invalidation and
owner-only atomic publication. Validate replacement bytes before retiring the
working selection; account for temporary double disk usage. Refuse replacement
of a running seat. A stopped overlay still depends on its backing file: changing
image requires an explicitly disclosed reset/revocation and new generation, or
retention of that old base until its references are released. Use the existing
reset/cleanup owners, never a global prune. An interrupted update must leave a
recoverable verified selection; test concurrent install/start/update and shared
cache writes. The current installer is not protected by the seat mutation lock
and publishes anchors separately from the release directory; include those
files and the persisted selection in crash-recovery reasoning.

## Canonical Owners And Cross-Cutting Gates

Paths below are relative to `src/aptl/` unless otherwise marked. These are
required passage points, not claims that every existing helper is sufficient
unchanged.

| Layer | Incumbents and required passage |
| --- | --- |
| Config and source shape | `core/config.py`: `AptlConfig`, `load_config`, `find_config`; `cli/_common.py`: `resolve_optional_config_for_cli`; `cli/config.py`. A durable source option enters the strict, non-secret config schema with a real consumer, defaults and validation. No parallel seat config JSON or untyped dictionary. Missing config may use defaults; malformed present config fails. Keep `api/routers/config.py` and `api/schemas.py` projections deliberate rather than returning registry credentials or all host state. |
| Release authentication and parsing | `appliance/models.py`, `release_models.py`, `manifest.py`, `release_validation.py`, `utils/strict_json.py`. Reuse closed models, duplicate-key rejection, canonical signed bytes, artifact size/digests, `verify_release_metadata()` and `verify_release_directory()`. A registry digest proves byte identity, not publisher authorization. Default acquisition needs independently provisioned public trust anchors available to a fresh install; never trust a key solely because it arrived with its image. Alternate sources must supply an explicit trust binding. |
| Registry/HTTP transport | Extend the transport seam in `appliance/public_install.py` and `PublicReleaseInstallDependencies`, building on `download.py`, `distribution.py` and `payload_content.py`. Validate bounded registry references, platform, media types, descriptor sizes/digests and the manifest-to-artifact binding before extraction. Use bounded HTTPS requests, safe resume, digest-addressed caches and traversal/link/special-file rejection. Public pull must work anonymously without host Docker. If registry auth is needed, validate challenge realm/service/scope against the selected authority, keep bearer values out of URLs/argv/logs, and never forward credentials to blob redirect hosts. Do not copy the HTTPS helper unchanged and assume it already implements registry auth. |
| Filesystem and state | `seat/paths.py`, `persistence.py`, `locking.py`, `overlay_cleanup.py`; `appliance/launch.py` and `build.py`. Preserve XDG defaults, explicit roots, contained relative paths, owner checks, no-follow regular-file access, restrictive modes, atomic writes and immutable launch descriptors. Check original paths before resolving away symlinks; containment alone does not establish ownership or eliminate races. No checkout-relative default state, host home mount or arbitrary recursive deletion. |
| Guest environment and payload shape | `appliance/offline.py:_release_environment()` accepts exactly the two non-secret scenario/version lines emitted by `inputs.py`. Its closed top-level payload validator and `inputs.validate_canonical_inputs()` must also accept the result. Do not append shell assignments for registry sources, tokens or build metadata. If that contract changes, update its canonical writer/parser and all verifiers together. Runtime secrets use `core/env.py` hydration, `load_dotenv`, `EnvVars`, placeholder checks and `core/credentials.py` rendering into private generated state, never baked `.env` or edits to tracked service config. |
| Guest lifecycle and deployment authority | `core/lab.py` start steps, `LabResult`, `StartupOutcome`/`StartupDiagnostic`, lifecycle guards, `DeploymentBackend`, `core/deployment/`, RAES admission and live readback. Guest setup invokes ordinary `aptl lab start --offline-staged`; it does not reproduce orchestration in shell. All range, web and helper Docker access stays on the admitted guest daemon, preserving socket binding, resource ownership and declared runtime checks. A newly started web container with Docker authority must appear in the real boundary inventory, not an exception list. |
| Host and hypervisor | `core/hostenv.py`, `appliance/build_host.py`, `seat/prereqs.py`, `allocation.py`, `vm.py`. Distinguish the physical hypervisor, a possibly virtualized launcher host, the seat guest and guest containers. Containers do not need another nested hypervisor. Check effective user KVM access and actual acceleration, architecture, firmware, CPU/RAM/headroom and disk capacity; CPU flags/tool versions alone do not prove a nested launch. Retain fixed QEMU argv, option-separator rejection, read-only launch share, private management sockets and PID/start-time/boot identity. No silent sudo, TCG fallback, writable host shares or host Docker socket. |
| Network and containment | `core/appliance_boundary.py`, `appliance_boundary_inventory.py`, `appliance_boundary_gate.py`; `seat/exposure.py`, `observation.py`, `readiness.py`; `appliance/loopback_proxy.py`. Preserve signed V2 policy, loopback-only typed `BoundaryEndpoint` mappings and guest/outer port separation. Keep restricted QEMU networking, host-wide allocation and live ownership/readback. Do not relax it to enable image pulls during boot. Readiness binds a fresh challenge, release, generation, guest boot/daemon and real capture to the full gate; a PID, listener or fixture boolean cannot substitute. V1 policy cannot be reinterpreted as V2. |
| Web, MCP and credentials | `api/deps.py:WebAuthSettings`, API/BFF origin/Host/session/WebSocket checks; `workbench/access.py`, `guest_binding.py`, `credentials.py`, `access_clients.py`, `client_files.py`; `seat/access.py`. Preserve operator authentication, participant role authorization, pinned SSH, revocable generation-bound discovery and owner-checked client-file updates. The guest MCP env must remain `mcpServers[server_id].env` with string port values and named ephemeral leases; use `aptl-mcp-common` config/TLS/CA validation. Do not copy host provider credentials, inherit host `DOCKER_HOST`, expose Docker or offer a general guest shell. A coarse recovery surface must not become an unauthenticated management API. |
| Errors, logging and persistence of evidence | Translate existing `ApplianceDownloadError`, `ApplianceDistributionError`, `AppliancePublicInstallError`, `ApplianceManifestError`, `ApplianceBuildError`, `OfflinePayloadError` and `WorkbenchConfigurationError` into bounded `SeatLauncherError`/existing lab outcomes at their boundary. Audit exception coverage: metadata download errors currently can escape the public installer wrapper. Reuse `get_logger()`, progress diagnostics, OTel, `redact()`, `RangeSnapshot.to_dict()` and runstore redaction. Never print raw Pydantic inputs, registry headers, subprocess stderr, environment dumps or secret-bearing guest logs. If adding boot diagnostics (QEMU stderr is currently discarded), bound and redact before persistence as well as display. No new exception tree, ad hoc token replacement or raw-log endpoint. |

## Local Image Cuts And Extensibility

Build on `scripts/appliance/build-local-candidate.sh`, `build-local-images.sh`,
`build-candidate.sh`, `qualify-candidate.sh`, `seal-release.sh` and
`accept-public-release.sh`, retaining their underlying `aptl appliance` commands.
Make one local build/qualify/seal/publish path authoritative; CI may check it,
but a package release or a second workflow implementation must not be required
to cut an image. Do not remove package QA/provenance or invent a new release
manager. Reconcile `docs/releasing.md`, appliance references and
`tests/test_appliance_release_workflow.py` with the resulting graph.

Separate **image release ID**, **APTL package version**, **exact source commit**,
**OCI transport digest**, **qcow2 digest**, and **seat generation**. Allow another
qualified image build from the same package version. Extend/version the incumbent
production source model for exact-commit local cuts rather than forging a version
tag or promoting `qualification-only` trust into production. Preserve old signed
schema verification and update every affected writer, verifier and signature
binding together.

The small extensibility seam is source coordinates (local release or registry
repository plus channel/digest and platform) resolved to the existing verified
release result. Keep it separate from prompts and QEMU. A mirror or a pinned older
image changes those coordinates, not lifecycle, policy or guest code. Configure
base image URL/digest/size and guest Python/architecture through the existing
build inputs. Admission must still reject unsupported host/guest combinations;
an `aarch64` schema value does not make the current x86-64 QEMU adapter portable.

Publish immutable qualified objects first. Advance the default public channel
only after anonymous acquisition and manual acceptance of those exact bytes;
retain the previous immutable release for rollback. Verify actual large-blob
upload/download behavior and package access, not repository visibility or an
authenticated developer cache. Reuse `redistribution.py` and the complete input
lock/provenance evidence. A public GHCR package must not contain signing keys,
provider/registry credentials, host SSH material, smoke-run state or session data.

## Boot, Packaging And Proof Guardrails

- Reconcile `appliance/guest/` provisioner, escaped systemd mount-unit name,
  launcher executable/Python paths, read-only 9p mount, virtio channels and
  service write restrictions. Verify execution as the real guest service and
  MCP identities. Preserve per-overlay first boot, retry/load-marker integrity,
  child-process failure handling and reboot reconciliation. An existing marker
  is not proof that every required image still exists.
- Reuse `_asset_manifest.py`, `hatch_build.py`, `core/assets.py`, `inputs.py`,
  `payload_content.py`, `input_images.py`, Python requirement exports/npm locks,
  `appliance/guest/system-packages.sha256` and `mcp/build-all-mcps.sh`. Include the
  actual web assets and runtime images plus SOC worker/child/helper closure.
  Preserve source-bundle exclusions; never scoop up a developer environment.
  Installed-wheel, guest Python ABI, Node and Debian-package closure must agree.
- Web startup must follow admitted scenario network creation and existing
  backend orchestration. Reuse host-port/endpoints and runtime network ownership;
  fixed web addresses can collide with realized nodes. Do not add retry loops,
  raw Compose commands, undeclared containers or a second topology to hide the
  failure. Preserve TLS/CA validation rather than using verification bypasses.
- Image a clean, shut-down base through `build.py` and `scan-golden.sh`, not the
  exercised seat overlay. A clean range startup creates secrets and identity
  again; stopping containers does not sanitize a disk. Clear machine/SSH identity,
  generated credentials, Docker writable state and evidence through the existing
  sanitization boundary, then qualify fresh overlays of the final image. Changes
  to disk bytes after qualification invalidate that proof.
- Use `docs/testing/smoke-test-plan.md` as the manual product rubric and the
  existing qualification/resource/native-client/browser receipts as evidence.
  Required proof covers full range behavior inside a real VM, smoke cleanup,
  clean range start and stop, reboot/load/setup behavior, and the final imaged
  artifact. Include real nested KVM when claiming nested-virtualization support,
  independent-host/concurrent-seat isolation, access revocation/reset, and
  anonymous fresh installed-CLI acquisition from GHCR. Record source/image
  digests, host/guest/tool versions, operator/time and observed pass/fail; do not
  infer working behavior from the donor branch or software tests.
- Exercise the consent/selection table manually: absent image, cached image
  offline, alternate source, refusal, EOF, auto-approval and confirmed update,
  plus failed/interrupted replacement without loss of the current base. Reuse
  focused `tests/test_appliance_*` CLI/transport/lifecycle/guest/boundary suites
  for regression coverage. Run targeted paths via `tools/run-targeted-tests.sh`
  and staged `pre-commit run`; full suites/coverage/whole-tree lint stay in CI.
  The issue's explicit manual VM proof remains required independently of CI.

Whole-repository scope includes the CLI and appliance owners above, core/RAES
deployment and workbench/API validators, Compose/container/config assets,
installed-package manifests and locks, qualification tests and docs,
`.github/workflows/`, `.ground-control.yaml` boundary routing, and the actual
filesystem/systemd/KVM/QEMU/registry layers. Current routing already includes
`appliance/guest/**`, `src/aptl/appliance/**` and `src/aptl/workbench/**`; the older
#1022 note's statement that these paths are omitted is stale.

## Non-Goals And Implementation Boundary

This preflight changes guidance only. It neither restores code nor boots,
cleans, images or publishes a range. It creates no implementation plan.

#1162 does not redesign TechVault/RAES, add internal security zones deferred to
#1127, introduce rootless guest Docker, support another hypervisor/OS, manage
provider accounts, add remote image-management APIs, or make package installs
perform privileged work. Do not replace canonical release/config/access schemas,
error hierarchies or lifecycle workflows with branch-local equivalents. Preserve
old immutable releases; never reset/rebase/drop history or force-push as a way
to restore behavior. No live-VM or public-image claim is established by this note.
