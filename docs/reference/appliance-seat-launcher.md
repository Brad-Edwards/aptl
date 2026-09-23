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

That is the whole first run. The launcher resolves the published seat image,
pulls it if this host does not already have it, creates a disposable overlay
over it, and boots. There is no install step, no release directory, and no
trust anchors to provision.

The image is pulled over plain HTTPS from the registry, so a seat host needs
QEMU and no Docker daemon. Integrity is the registry's content addressing:
every blob is fetched by digest and rejected unless its bytes hash to that
digest.

To run a different image, such as your own build or a pinned digest, point
`--image` at it:

```bash
aptl seat start --image ghcr.io/your-org/your-seat:latest
aptl seat start --image ghcr.io/your-org/your-seat@sha256:<digest>
```

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

Checking for a newer image is separate from adopting one. The check is
rate-limited rather than run on every start, never gates the boot path, and
fails open, so a registry outage or an offline host cannot delay or prevent a
seat starting. When a newer image exists, the launcher says so and keeps
booting what it had:

```text
a newer seat image is available: sha256:be21… — adopt with `aptl seat update`
```

Adopting takes effect on the next start; a running seat is untouched:

```bash
aptl seat update                      # adopt what the reference resolves to now
aptl seat update --to sha256:<digest> # roll back to an image already cached
```

Adoption keeps the previous disk, which is what makes rollback possible. A
digest-pinned reference is never checked and never prompts.

Cached images are large. List them, with the references that select them, and
remove the ones nothing selects:

```bash
aptl seat images
aptl seat images --prune
```

Pruning never removes an image a reference currently selects, so a rollback
target survives while it is still selected somewhere.

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

Open the participant kiosk browser (presentation only):

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
  instances/
    seat-01.qcow2            # disposable overlay
    seat-01.state/           # guest-only overlay identity

~/.cache/aptl/appliance/
  <digest>/seat-disk.qcow2   # shared, read-only, content-addressed
  refs/<reference>.json      # which digest each reference selects
```

## Building the image

The published image is baked by the release workflow on an ordinary hosted
runner. `scripts/appliance/build-seat-image.sh` fetches the pinned Ubuntu base
by digest, builds this project's container images from the exact source,
exports them alongside the pinned third-party TechVault images derived from
`docker-compose.yml`, and installs the whole set into the guest with
`appliance/guest/provision-seat.sh`. The result holds Docker, the APTL runtime
and every container image the lab starts, so a participant's first boot
resolves nothing and pulls nothing.

`scripts/appliance/publish-seat-image.sh` pushes the disk and its config blob
to `ghcr.io/<owner>/aptl-seat` as an OCI artifact, tags it with the content
key, and moves the release tag and `latest` onto it. Publication is proven by
pulling the result without credentials.

A release only bakes when the image would differ.
`scripts/appliance/seat-image-key.sh` digests the guest assets, container
definitions, locked Python closure, participant profile and pinned base; if an
image already exists under that key the workflow skips the bake and just moves
the tags. Editing a Dockerfile changes the key. Editing documentation does
not.

To bake locally:

```bash
export APTL_BASE_IMAGE_URL=... APTL_BASE_IMAGE_SHA256=sha256:...
export APTL_GUEST_PYTHON_VERSION=3.14
scripts/appliance/build-seat-image.sh
```

It needs `libguestfs-tools`, `qemu-utils`, Docker, and enough free disk for
the image archive and the baked disk at once.

## Diagnostics

CLI failures emit bounded JSON with stable codes such as `no-kvm`, `low-disk`,
`corrupt-overlay`, `image-unavailable`, `failed-readiness`, and boundary
inventory codes. Raw QEMU/libvirt stderr, guest logs, and credentials are
never returned.

## Related documents

- [VM-only seat containment](../adrs/adr-060-vm-only-seat-containment.md)
- [Appliance network boundary](../components/appliance-boundary.md)
- [Host MCP access](host-mcp-access.md)
