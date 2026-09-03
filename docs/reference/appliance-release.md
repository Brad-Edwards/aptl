# Disposable appliance release

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
- all nine required artifacts have their byte size and SHA-256 digest bound
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

The release host needs Python 3.11 or later, `qemu-img`, and libguestfs tools
providing `virt-customize` and `virt-sysprep`. The pinned Ubuntu base image must
already contain systemd, Python with pip, and Docker Engine. The supported
participant profile requires at least 8 vCPUs, 16 GiB RAM, 100 GiB available
disk, and hardware virtualization.

Network access is permitted while a release engineer resolves and stages
version-pinned inputs. The subsequent payload assembly and golden-image build
are deliberately offline: they contain no checkout, dependency resolution,
image pull, image build, or package-repository step.

## Stage the offline payload

Create a closed staging directory with exactly these entries:

| Entry | Purpose |
| --- | --- |
| `wheelhouse/` | The `aptl_labs-*.whl` wheel and all locked Python wheels |
| `project.tar` | Checkout-free project assets from the exact source commit |
| `oci-images.tar` | All digest-pinned container images in the APP-2 asset lock |
| `appliance-release.env` | Non-secret scenario and exact `APTL_APPLIANCE_VERSION` lines |
| `aptl-appliance-first-boot` | First-boot script from `appliance/guest/` |
| `aptl-appliance-first-boot.service` | Corresponding systemd unit |

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

The command checksum-verifies every input, converts and resizes the base,
provisions it with `virt-customize --no-network`, removes machine identity,
SSH host keys, logs, caches, Docker writable state, APTL overlay state, and run
state with `virt-sysprep`, executes the clean-golden scanner offline, runs
`qemu-img check`, and publishes the disk and inventory as read-only,
create-once outputs. A failed candidate cannot replace an existing release.

## Qualify and seal

Stage these nine non-empty release artifacts beneath one release directory:

1. golden disk;
2. offline payload;
3. APP-2 participant profile;
4. APP-2 participant readiness suite;
5. APP-2 participant asset lock;
6. signed APP-2 participant qualification report;
7. APP-1 appliance boundary policy;
8. clean-golden inventory; and
9. appliance machine-drill report.

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
signature checks. Unknown fields, duplicate identifiers or paths, unsafe
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
