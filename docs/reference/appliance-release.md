# Disposable appliance release

Current delivery uses the signed V2 [VM-only containment contract](../adrs/adr-060-vm-only-seat-containment.md).
It does not claim APP-1 internal-zone isolation, deferred to #1127. Existing V1
policies still require their stronger enforcement; signature or qualification
checks must not silently reinterpret them as VM-only releases.

APTL appliance releases package a read-only golden qcow2 guest and every
participant dependency needed for an offline first boot. Each lab instance is
a disposable qcow2 overlay. Destroying that overlay destroys its credentials,
Docker state, and run evidence; the golden disk is never opened for writing.

This is a release-engineering interface. The participant launcher, reset
controls, and recovery UI are implemented by [`aptl seat`](appliance-seat-launcher.md)
(issue #824).

## Trust and lifecycle model

An appliance release is admitted only when all of these statements are true:

- the source tag is exactly `v<aptl-version>` and names a full source commit;
- all eleven base artifacts plus canonical-input and redistribution-review
  evidence have their byte size and SHA-256 digest bound
  into a canonical RFC 8785 manifest;
- the manifest has a valid Ed25519 signature from the configured release trust
  anchor;
- the APP-2 profile, asset lock, signed qualification report, APP-1 boundary
  policy, clean-golden inventory, and two-machine drill agree with the
  manifest;
- qualification reports zero downloads, pulls, builds, or package resolution
  during offline startup;
- local KVM and hosted delivery use the same golden and offline payload bytes;
- the golden disk is qcow2, read-only, and used only as a backing file; and
- upgrades and rollbacks select another verified golden release and create a
  new overlay. In-place guest upgrades are not supported.

`aptl appliance inspect` prints only the verified version, content identities,
architecture, and minimum host resources. It does not expose artifact paths,
machine identities, or per-instance credentials.

## Build host prerequisites

The release host needs Python 3.11 or later, the guest target Python, `qemu-img`,
and libguestfs tools providing `virt-customize`, `virt-resize`, and
`virt-sysprep`. The pinned Ubuntu base image must
already contain systemd, Python with pip, and Docker Engine. The supported
participant profile requires at least 8 vCPUs, 32 GiB RAM, a 250 GiB-capacity
disk, 120 GiB of free runtime headroom, and hardware virtualization. The sparse
guest disk retains its 250 GiB virtual capacity; the launcher reserves the
separately signed peak-runtime ceiling rather than requiring the full virtual
capacity to be free.

Run the non-mutating prerequisite report before acquiring large inputs:

```bash
aptl appliance doctor --build-root build
```

The report checks Linux/x86-64, available build-root space, QEMU, and both
libguestfs tools. It reports missing packages but never installs them.

## Build and qualify an exact local commit

The development candidate path builds directly from a clean checkout; it does
not require a Git tag, GitHub Release, GHCR login, or production signing key.
It rebuilds all thirteen project-owned OCI images under their canonical local
names, assembles the wheel and complete offline closure, downloads the pinned
Ubuntu 26.04 `20260823` qcow2 by its recorded size and SHA-256, and signs the
candidate with a throwaway qualification-only key:

```bash
sudo apt-get install libguestfs-tools
aptl appliance doctor --build-root build
git status --porcelain
git rev-parse HEAD
scripts/appliance/build-local-candidate.sh
```

The command refuses a tracked-file diff so the candidate manifest can bind the
exact commit as `commit:<full-sha>`. The resulting files are under
`build/appliance/candidate-publication/`; they are deliberately not shaped as a
production release and `seal-release.sh` cannot promote their development
source identity.

Run the real two-seat KVM qualification locally with a separate temporary
qualification key. The key is only for local evidence and must not be reused as
the protected production qualification key:

```bash
openssl genpkey -algorithm ED25519 -out build/local-qualification.pem
APTL_CANDIDATE_PUBLICATION="$PWD/build/appliance/candidate-publication" \
APTL_QUALIFICATION_OUTPUT="$PWD/build/local-machine-a.json" \
APTL_QUALIFICATION_SEATS=2 \
APTL_QUALIFICATION_SIGNING_KEY_PEM="$(<build/local-qualification.pem)" \
scripts/appliance/qualify-candidate.sh
rm build/local-qualification.pem
```

This exercises real KVM boot, concurrent overlays and mappings, full guest
readiness, browser reachability, authenticated Claude and Codex MCP calls,
revocation, reset, recovery, tamper rejection, and resource measurements. It
does not replace the two independent machines and production trust anchors
required before public release sealing.

Network access is permitted while a release engineer resolves and stages
version-pinned inputs, including the canonical npm builds. The subsequent payload assembly and golden-image build
are deliberately offline: they contain no checkout, dependency resolution,
image pull, image build, or package-repository step.

## Stage the offline payload

Run `aptl appliance assemble-inputs` from the installed APTL wheel, using a
pre-acquired platform-specific hashed wheelhouse, Docker-save image archive,
and a JSON map of canonical image roles to `sha256:` image config IDs. The
command materializes wheel assets, builds the frontend and every MCP from npm
locks, writes the full-TechVault profile, and validates the nested input closure.
It does not build a VM or qualify an offline boot.

```bash
aptl appliance assemble-inputs --staging-dir build/offline-staging \
  --wheelhouse build/wheelhouse --image-archive build/oci-images.tar \
  --image-roles build/image-roles.json \
  --target-python-version 3.14 --target-architecture x86_64
aptl appliance validate-inputs --staging-dir build/offline-staging
```

The canonical staging directory contains exactly these entries:

| Entry | Purpose |
| --- | --- |
| `inputs.json` | Full pack identity, platform, image roles and v2 content lock |
| `requirements.txt` | Hash-pinned APTL `[web]` and transitive wheel closure |
| `wheelhouse/` | The `aptl_labs-*.whl` wheel and all locked Python wheels |
| `project.tar` | Immutable wheel assets plus built frontend/MCP runtime dependencies and full profile |
| `oci-images.tar` | Complete scenario, helper and child image IDs with verified configs and layers |
| `appliance-release.env` | Non-secret scenario and exact `APTL_APPLIANCE_VERSION` lines |
| `aptl-appliance-first-boot` | First-boot script from `appliance/guest/` |
| `aptl-appliance-first-boot.service` | Corresponding systemd unit |
| `aptl-launch.mount` | Read-only 9p launch-share mount installed as the path-escaped systemd unit |

The wheelhouse must contain exactly one `aptl_labs-*.whl`, and its version must
equal `APTL_APPLIANCE_VERSION`. Symlinks, unexpected files, empty archives,
non-wheel wheelhouse entries, and secret environment values are rejected.
Assemble the reproducible USTAR payload:

```bash
aptl appliance bundle \
  --staging-dir build/offline-staging \
  --output build/inputs/offline-payload.tar
```

Archive entries are sorted and normalized to root ownership and epoch
timestamps, so identical staged bytes produce an identical payload digest.

## Build the golden image

Copy `appliance/guest/provision-offline.sh` and
`appliance/guest/scan-golden.sh` into the contained build root. Prepare a
strict JSON request with these fields:

| Field | Value |
| --- | --- |
| `schema_version` | `aptl.golden-image-build/v1` |
| `base_image_path`, `base_image_digest` | Safe relative qcow2 path and exact `sha256:` digest |
| `offline_payload_path`, `offline_payload_digest` | Path ending in `offline-payload.tar` and exact digest |
| `provisioner_path`, `provisioner_digest` | Offline provisioner and exact digest |
| `scanner_path`, `scanner_digest` | Clean-golden scanner and exact digest |
| `output_image_path` | New golden qcow2 path |
| `inventory_output_path` | New clean-golden inventory path |
| `virtual_size_bytes` | At least 100 GiB |

Then run:

```bash
aptl appliance build \
  --build-root build \
  --request build/golden-build.json
```

The command checksum-verifies every input, rejects external qcow2 backing/data
references, creates the requested target disk, expands the Ubuntu root partition
and filesystem with `virt-resize`,
provisions it with `virt-customize --no-network`, removes machine identity,
SSH host keys, logs, caches, Docker writable state, APTL overlay state, and run
state with `virt-sysprep`, executes the clean-golden scanner offline, runs
`qemu-img check`, and publishes the disk and inventory as read-only,
create-once outputs. A failed candidate cannot replace an existing release.

## Large release assets

The signed release manifest continues to identify the canonical qcow2 and
offline payload bytes. If either cannot be uploaded as one release asset,
create ordered transport chunks and an independently signed reconstruction
index with the configured release trust key:

```bash
aptl appliance split-distribution \
  --source dist/appliance/v5.5.0/aptl-golden.qcow2 \
  --output-dir dist/transport/aptl-golden \
  --release-id aptl-v5.5.0-x86_64 \
  --manifest-digest sha256:MANIFEST_DIGEST \
  --private-key /secure/release-signing.pem
```

After downloading the index, detached signature, and all named chunks,
reconstruct automatically:

```bash
aptl appliance reconstruct-distribution \
  --index downloads/aptl-golden.qcow2.distribution.json \
  --signature downloads/aptl-golden.qcow2.distribution.sig.json \
  --chunks-dir downloads --public-key /etc/aptl/trust/release-public.pem \
  --output cache/aptl-golden.qcow2
```

The command authenticates canonical index bytes with Ed25519, verifies every
ordered chunk and the reconstructed size/digest, and publishes the output
create-once. Chunking is transport only; consumers must still run `aptl
appliance verify` on the complete reconstructed release directory.

For a public GitHub Release, `fetch-distribution` performs the anonymous HTTPS
download, authenticated cache staging, and reconstruction in one operation:

```bash
aptl appliance fetch-distribution \
  --repository OWNER/REPOSITORY --tag v5.5.0 \
  --release-id aptl-v5.5.0-x86_64 \
  --artifact-name aptl-golden.qcow2 \
  --public-key appliance-release-public.pem \
  --cache-dir "$XDG_CACHE_HOME/aptl/appliance" \
  --output release/artifacts/aptl-golden.qcow2
```

`release-public.pem` and `qualification-public.pem` are independently
provisioned trust anchors. A downloaded copy may be compared with those anchors
for convenience, but a key fetched beside the chunks is never trusted merely
because it came from the same release page. The release workflow pins both
public keys in protected repository variables and refuses sealing or public
acceptance when the corresponding private/qualification key differs.

End users normally use the higher-level installer, which performs the metadata
download, both authenticated reconstructions, complete release verification,
and atomic publication into their private seat state:

```bash
aptl seat install --tag v5.5.0 \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem
aptl seat start
```

The lower-level distribution commands remain available for release engineering
and diagnostics.

Publication also requires a protected `aptl.redistribution-review/v1` approval
for the exact source commit and canonical-input digest. The review must cover
the guest base image, every unique OCI image identity, every Python wheel, and
every packaged npm lock. Sealing signs that review into the release and emits
`THIRD-PARTY-NOTICES.md`; missing, stale, duplicate, or partial approvals stop
publication before the production signature is created.

The release environment supplies that reviewed document through the protected
`APTL_REDISTRIBUTION_REVIEW_JSON` secret. Its closed schema contains
`schema_version`, `decision: "approved"`, `authority`, UTC `reviewed_at`, the
40/64-hex `source_commit`, `canonical_inputs_digest`, and `entries`. Each entry
has `kind` (`base-image`, `oci-image`, `python-wheel`, or `npm-lock`), the exact
`subject` and `sha256`, an HTTPS `source_url`, `license_expression`, and the
notice text that must be retained. Subject identities are derived from the
qualified candidate; a generic approval or approval for another candidate is
rejected.

## Download and cache

Stage each release asset before offline guest startup using its published
digest and exact byte size. The cache resumes a matching partial transfer,
requires HTTPS across redirects, preflights free space, rejects oversized or
short responses, and publishes verified bytes under their SHA-256 identity:

```bash
aptl appliance stage-download \
  --url https://github.com/OWNER/REPOSITORY/releases/download/TAG/ASSET \
  --cache-dir "$XDG_CACHE_HOME/aptl/appliance" \
  --filename aptl-golden.qcow2 \
  --sha256 sha256:DIGEST \
  --size-bytes EXACT_SIZE
```

For a split asset, stage the signed index, its detached signature, and every
named chunk, then run `reconstruct-distribution`. A later invocation reuses an
unchanged verified cache entry. Downloads and reconstruction finish before
`aptl seat stage`; guest startup performs no network access.

## Qualify and seal

Stage these thirteen non-empty #1022 release artifacts beneath one release
directory (the historical schema keeps canonical inputs optional only for older
fixtures):

1. golden disk;
2. offline payload;
3. APP-2 participant profile;
4. APP-2 participant readiness suite;
5. APP-2 participant asset lock;
6. signed APP-2 participant qualification report;
7. the exact successful participant run record;
8. its correlated range snapshot;
9. APP-1 appliance boundary policy;
10. clean-golden inventory;
11. appliance machine-drill report; and
12. canonical full-TechVault inputs; and
13. the exact-closure redistribution approval and notices.

The drill report must contain successful results from at least two distinct
supported machines. Each must pass the build, offline boot, participant smoke,
rollback, and overlay-destruction checks. The report also records clean-golden,
read-only base, distinct-overlay-identity, and failed-candidate-preservation
results. A release cannot be sealed with placeholders or fewer machines.

Keep the release metadata template, qualification public key, release private
key, and release public key outside the release directory:

```bash
aptl appliance prepare \
  --release-dir dist/appliance/v5.1.1 \
  --template release-template.json

aptl appliance seal \
  --release-dir dist/appliance/v5.1.1 \
  --private-key /secure/release-signing.pem \
  --qualification-public-key /secure/qualification-public.pem

aptl appliance verify \
  --release-dir dist/appliance/v5.1.1 \
  --public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem
```

Preparation derives artifact sizes and digests from the staged bytes. Sealing
revalidates all reused contracts and the qualification attestation, then
creates `SHA256SUMS` and `manifest.sig.json`. Verification checks the signature,
manifest, checksums, every artifact, all cross-bindings, and all evidence.
The qualification report must contain the exact duplicate-free readiness check
set and participant surface declared by the signed profile and readiness suite.
Consumer verification repeats both the release and independent qualification
signature checks, verifies the run-record/snapshot digests and correlation, and
enforces measured profile budgets. Unknown fields, duplicate identifiers or paths, unsafe
paths, unpinned helper images, a mismatched APTL wheel, or inconsistent evidence
fail closed.

## Create and run a local instance

Place the verified release under a per-launch directory and create the immutable
launch projection. The observation ID comes from the authenticated outer
launcher/host observation:

```bash
aptl appliance prepare-launch \
  --release-dir /srv/aptl-appliance/launch/release \
  --public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem \
  --host-observation-id sha256:<host-observation-digest> \
  --output /srv/aptl-appliance/launch/appliance-launch.json
```

The descriptor carries the verified manifest, payload, policy, helper-image,
version, and golden-disk identities. It is create-once and read-only. Create an
overlay request that binds both the golden and descriptor:

```json
{
  "schema_version": "aptl.overlay-create/v1",
  "golden_image_path": "releases/v5.1.1/aptl-golden.qcow2",
  "golden_image_digest": "sha256:<verified-golden-digest>",
  "launch_descriptor_path": "launch/appliance-launch.json",
  "launch_descriptor_digest": "sha256:<launch-descriptor-digest>",
  "overlay_path": "instances/seat-01.qcow2"
}
```

Create the overlay:

```bash
aptl appliance create-overlay \
  --appliance-root /srv/aptl-appliance \
  --request /srv/aptl-appliance/seat-01.json
```

The command refuses a writable or digest-mismatched golden disk, requires the
matching launch descriptor, never replaces an existing overlay, and uses fixed
`qemu-img` arguments with the golden as a qcow2 backing file. Attach only the
new overlay to QEMU/KVM. Mount the launch directory read-only at
`/run/aptl-launch`; it contains `appliance-launch.json`, the `release/`
directory, `release-public.pem`, and `qualification-public.pem`.

The guest's idempotent systemd first-boot service creates unique owner-only
identity and credentials on the overlay, loads the staged OCI archive once,
and invokes `aptl lab start --offline-staged` with the descriptor and both trust
anchors. Startup reverifies the release, qualification, and descriptor, then
puts the manifest payload digest into `ApplianceBoundaryBinding` before RAES
network-policy enforcement or service realization. Ordinary reboots reuse the
overlay identity while repeating release admission.

The local launcher and a hosted importer must attach the exact same verified
golden payload; provider metadata and the disposable overlay remain outside the
payload. Hosted per-seat fallback is tracked in issue #825.

## Reset, rollback, and evidence

- Reset: power off the VM and delete only its overlay. Create a new overlay
  from the same verified golden. Do not delete or modify the golden.
- Upgrade: verify the newer release, select its golden, and create a new
  overlay.
- Rollback: verify the previously retained release, select its golden, and
  create a new overlay. Never downgrade an existing overlay in place.
- Failure: leave the active release selected. Candidate build or seal failures
  are not promoted and cannot replace it.

Retain the tagged source identity, canonical manifest, detached signature,
`SHA256SUMS`, clean-golden inventory, APP-2 qualification, and two-machine drill
with the release. These records connect the version and checksums to readiness
and rollback evidence.

## Public release delivery

The release workflow builds the repository-owned container closure from the
exact release tag into private
`ghcr.io/<owner>/aptl-candidate/<image>:<tag>` staging packages. A dedicated
builder records those immutable staging references in the offline payload and
creates one signed qualification-only candidate. Two distinct KVM
machines exercise that exact candidate; one boots two seats concurrently. A
separate sealing runner aggregates their evidence and signs the unchanged
golden and payload bytes. Only after sealing does the workflow promote those
same digests to `ghcr.io/<owner>/aptl/<image>:<tag>`, make each destination
package public, log out, and prove anonymous pulls. The public GitHub Release
receives a metadata tar, both public keys, and signed chunks smaller than 2 GiB
for both large artifacts.

Publication is not the final gate. A no-permissions KVM job logs out of GHCR,
anonymously pulls every image, downloads the GitHub Release assets without an
API token, reconstructs and verifies the release, boots it, makes real read-only
Claude and Codex MCP calls, proves those stale calls fail after stop, and resets
the overlay.

## Canonical inputs and host access

Canonical inputs bind every wheel and every project/build file by SHA-256. The
validator checks wheel tags, transitive dependencies including extras, package
identity, required builds, exact image roles, Docker/OCI layer graphs and the
immutable assets inside the delivered APTL wheel. Validation runs on the declared
Python/architecture target. It is a software input check, not offline-boot proof.
Historical six-entry guided payload fixtures remain readable; new full-TechVault
assembly requires the two additional entries above.

A host-MCP-enabled release also carries a `canonical-inputs` artifact equal to
the payload's `inputs.json`, a matching `canonical_inputs_digest`, and
`host_mcp_contract: aptl.restricted-ssh-mcp/v1` in delivery metadata. The signed
boundary policy must declare that same contract and exactly one host-MCP guest
publication. Launch descriptors preserve those identities. The original nine
artifacts, release and qualification signatures, offline qualification and
independent-machine drills remain mandatory. #1022 supplies actual VM builds,
boot and key wiring, port mappings, concurrent seats and publication.
