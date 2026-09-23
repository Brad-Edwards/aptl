# Appliance seat launcher

A seat is one disposable VM per user running the ordinary full TechVault lab,
using [VM-only containment](../adrs/adr-060-vm-only-seat-containment.md).
Authenticated access and physical-host/cross-seat isolation remain required.
Additional isolation and controlled egress between workloads inside a guest are
not promised; that work is tracked in #1127. The V2 boundary policy the image
carries identifies this contract explicitly.

The launcher uses restricted QEMU user networking: the guest cannot initiate
connections to the physical host, another seat, or the external network. Only
the declared host-to-guest port forwards remain available. That restriction
does not separate workloads inside the VM.

## Security boundary

The seat is the preferred path when AI agents will operate the range or when
multiple users share a physical host. Direct `aptl lab start` places the
intentionally vulnerable workloads, MCP tooling, and Docker-authorized control
components on the selected host Docker engine. A seat instead places that
rootful Docker daemon and the entire range inside a dedicated disposable VM;
only loopback port mappings and the restricted authenticated MCP transport
cross the VM boundary. Compromise of an ordinary lab container is therefore
contained by an additional KVM/QEMU boundary before it reaches the physical
host or another seat.

That boundary is risk reduction, not a claim that VM escape is impossible. An
advanced model with tool access can research, adapt, and attempt exploit chains
against the guest kernel, emulated devices, QEMU, KVM, or the host kernel. A
vulnerability in one of those layers may permit escape. Operators who care
about that consequence should keep the virtualization stack patched, avoid
unnecessary QEMU devices and host mappings, run seats on a dedicated and
rebuildable host, keep unrelated secrets and workloads off it, restrict the
surrounding network, and monitor active sessions.

Inside one seat, all TechVault workloads share the guest boundary. A compromise
may affect other containers, credentials, or evidence in that same VM. Reset
destroys the overlay and revokes the previous generation; it does not turn a
known-compromised physical host back into a trusted one.

## Prerequisites

The physical host must satisfy the resources the seat image declares:

- Linux with hardware virtualization (`/dev/kvm`)
- `qemu-img`, `qemu-system-x86_64`, and read-only OVMF UEFI firmware
- available CPU/RAM at or above the image's minimums, and free disk at or
  above its declared runtime reservation
- [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) for first acquisition and updates
- No dependency on host Docker for seat operations

Each user who launches a seat needs read/write access to `/dev/kvm`. On the
usual Linux packaging this means membership in the `kvm` group followed by a
new login session. The launcher reports every failed host prerequisite in one
bounded error instead of stopping after the first missing resource or tool.
On Debian/Ubuntu hosts, install the complete host dependency set once with:

```bash
sudo apt-get install qemu-system-x86 qemu-utils ovmf
```

No shared `seat-state` directory is required. Each user's seat state is
created privately below that user's own `$XDG_STATE_HOME` or home directory.

## Start a seat

```bash
aptl seat start
```

The first run asks before any registry lookup or download. Declining, pressing
Enter, or providing no stdin leaves the image and seat untouched. `--yes` (or
`-y`) explicitly approves acquisition in automation.

The launcher verifies the immutable OCI manifest with Cosign and the publisher
public key bundled in the CLI, then checks the config and disk against their
signed digests. Registry login and Docker are unnecessary. A missing Cosign
binary, invalid signature, missing trusted key, or corrupt selected image fails
closed. Cosign's transparency-log checks remain enabled.

To select an alternate image, provide its independently obtained public key:

```bash
aptl seat start --image ghcr.io/your-org/your-seat:stable --public-key publisher.pub
aptl seat start --image ghcr.io/your-org/your-seat@sha256:<digest> --public-key publisher.pub --yes
```

Selection precedence is `--image` / `APTL_SEAT_IMAGE`, `seat.image` in
`aptl.json`, the existing seat's source, then the default GHCR channel.
`seat.public_key` configures an alternate trust key. An alternate source never
falls back to the default. Public keys are scoped to the selected repository;
credentials or keys embedded inside downloaded images do not establish trust.

`seat start` selects distinct outer ports automatically. When the image's
boundary policy requires host MCP access, it creates an owner-only Ed25519
transport identity, enrols the current user for that seat generation, and
safely updates the Claude and Codex project configurations in the current
directory. Provider authentication remains entirely user-owned and is neither
read nor copied.

State defaults to the current user's private roots: `$XDG_STATE_HOME/aptl/seat`
for the seat and `$XDG_CACHE_HOME/aptl/appliance` for the image cache, or the
`~/.local/state` and `~/.cache` equivalents. `--seat-root` and `--image-cache`
remain available for managed deployments.

## Updates are never forced

The digest an image reference first resolves to is sticky. A seat keeps
booting that digest until you adopt another, so publishing a new `:latest`
never changes what a running fleet boots.

Warm starts use the verified selected image without contacting the registry.
A missing or corrupt selection reports an error; it does not silently download
another image. Explicit updates ask for permission to download, reset the
stopped seat and revoke its access, and remove the superseded cached image:

```bash
aptl seat stop
aptl seat update
aptl seat start
# Automated replacement, with the same verification and admission checks:
aptl seat update --yes
```

A running VM refuses replacement. Download, signature or host-admission failure
preserves the prior selection and overlay. Successful replacement resets the
seat to a new generation. Other seats retain their own immutable disks, launch configs, and publisher
verification records, so they can restart offline after shared cache retirement.
Interrupted reset is a recoverable failure: stop the seat and repeat reset
before use. A pinned reference remains pinned until explicitly changed.

List cached images or confirm removal of entries no reference selects:

```bash
aptl seat images
aptl seat images --prune
```

`seat update --to sha256:<disk-digest>` selects a previously verified disk only
while it remains cached under the same repository and trust key. Superseded
images are normally deleted; rollback therefore requires a retained selection
or acquiring the desired immutable image reference again.

## Reserving operator-selected ports

Stage a seat with one repeated typed mapping for every endpoint the image
publishes:

```bash
aptl seat stage \
  --seat-id seat-01 \
  --mapping participant,tcp,127.0.0.1,10443,127.0.0.1,443 \
  --mapping recovery,tcp,127.0.0.1,11443,127.0.0.1,9443
```

The six mapping fields are audience, protocol, outer address, outer port,
guest address, and fixed guest port.

Duplicate outer endpoints, incomplete mappings, and destinations absent from
the image's publication policy fail closed. A staged mapping cannot be changed
during start; reset creates a new generation.

Automatic selection, explicit endpoint handoff, and capacity admission are
serialized across launcher processes. Each QEMU seat publishes its CPU, RAM,
and disk reservation in a fixed `fw_cfg` argument. Before launch, the allocator
sums every visible APTL QEMU reservation and rejects the new seat if the
concurrent total would exceed host capacity. The available-memory check also
preserves host headroom of at least 8 GiB or 10% of physical RAM, whichever is
greater. A seat is refused before QEMU launches if it would consume that
reserve; this protects the host SSH service and other workloads.

Readiness is not inferred from a live PID or listener: the tracked QEMU
instance, real forbidden-reachability probe, guest boot/daemon observation, and
complete appliance boundary gate must all agree for the current generation.

Open the participant kiosk browser. Login uses an owner-private bootstrap file;
the token is absent from browser process arguments and printed plans. The file
is replaced on the next launch and removed on reset:

```bash
aptl seat open-kiosk
```

Inspect coarse health (no credentials):

```bash
aptl seat status
```

## Reset and recovery

Security reset destroys the overlay and recreates a fresh one over the same
image. It is not a reboot, logout, or in-guest repair.

```bash
aptl seat reset --seat-id seat-01
```

Instructor recovery performs reset then start:

```bash
aptl seat recover --seat-id seat-01
```

After a physical-host reboot, reconcile persisted seat metadata before reuse:

```bash
aptl seat reconcile
```

When reconciliation reports `host-reboot-detected` or `vm-not-running`, run
`recover` before returning the seat to a participant.

## Directory layout

```text
~/.local/state/aptl/seat/
  seat-state.json
  vm.pid                     # PID + procfs start/executable identity
  launch/
    appliance-launch.json    # create-once launch projection
    boundary-policy.json     # the exact policy bytes the gate is bound to
  image/                     # this generation's retained disk/config/trust
  runtime/kiosk/login.html   # owner-private browser bootstrap; removed on reset
  instances/
    seat-01.qcow2            # disposable overlay
    seat-01.base.qcow2       # retained immutable backing file
    seat-01.state/           # guest-only overlay identity

~/.cache/aptl/appliance/
  <digest>/seat-disk.qcow2   # shared, read-only, content-addressed
  refs/<reference>.json      # which digest each reference selects
```

## Building the image

Image cuts are local operations, independent of Release Please and PyPI. Use a
clean checkout of the intended source commit. The build needs KVM,
`libguestfs-tools`, QEMU, Docker, Node 22, Python 3.14, and enough disk for the
source, image archive, expanded guest and compressed output together.
The build refuses to proceed without read/write access to `/dev/kvm`; join the
`kvm` group and start a new login session if necessary.
Capacity admission uses the disk's declared virtual size, not its compressed
size. The default is 250 GiB; `APTL_SEAT_DISK_GIB` selects another capacity.

```bash
APTL_SEAT_BUILD_ROOT="$PWD/build/seat-cut" scripts/appliance/build-seat-image.sh
scripts/appliance/qualify-seat-image.sh build/seat-cut/out/seat-disk.qcow2
```

The build downloads a digest-pinned Ubuntu base, builds project containers and
MCP/web assets, stages the complete TechVault closure, installs the hash-locked
runtime offline, sanitizes and scans the guest, and writes its launch config.
`scripts/appliance/seat-base-image.env` holds the base pin. Every participant
boot loads local image bytes and starts the normal admitted lab without pulling
containers. The qualification script exercises real Docker, range and semantic
MCP operations in a disposable VM; also exercise the actual `aptl seat` path,
participant web, cleanup, clean-range startup, stop and reset before publishing.
Record source, disk and config hashes with the observed results. The build
writes `seat-build.json` binding those bytes to the source commit. Dirty builds
are diagnostic artifacts and cannot be published; changed output bytes also
fail publication. This local build record is not a SLSA provenance attestation.

The publisher requires ORAS, Cosign, a GHCR write token, and the private signing
key corresponding to the CLI's public anchor. Keep signing material outside the
checkout's tracked files and guest payload. Supply credentials through the
process environment or a key-provider mechanism; do not put them in shell
history. Encrypted file keys use Cosign's `COSIGN_PASSWORD` environment variable.

```bash
# REPOSITORY_OWNER, GHCR_TOKEN and APTL_SEAT_SIGNING_KEY already supplied securely
scripts/appliance/publish-seat-image.sh build/seat-cut/out
```

The script pushes the disk/config by content key, checks anonymous access, signs
the immutable manifest and verifies its signature. Its output is the immutable
reference. `APTL_SEAT_IMAGE_TAG` optionally adds an immutable human-readable tag.
Test the immutable reference with a fresh CLI and empty private cache before
promoting: rerun with `APTL_SEAT_PUBLISH_LATEST=1`. The script reuses existing
content. Anonymous checks try at most three times and stop immediately on HTTP
401/403. A registry failure requires diagnosis; repeatedly rebuilding an image
cannot repair package permissions or a broken tag.

New GHCR packages default to private. The package owner must make the VM package
public before anonymous acquisition can succeed. The publisher isolates its
registry login from the operator's existing Docker configuration. Neither its
authentication token nor the signing key is copied into the image. A signature
proves publisher authorization; the separate manual record proves the range
operations actually observed.

## Diagnostics

CLI failures emit bounded JSON with stable codes such as `no-kvm`, `low-disk`,
`corrupt-overlay`, `image-unavailable`, `failed-readiness`, and boundary
inventory codes. Raw QEMU/libvirt stderr, guest logs, and credentials are
never returned.

## Related documents

- [VM-only seat containment](../adrs/adr-060-vm-only-seat-containment.md)
- [Appliance network boundary](../components/appliance-boundary.md)
- [Host MCP access](host-mcp-access.md)
