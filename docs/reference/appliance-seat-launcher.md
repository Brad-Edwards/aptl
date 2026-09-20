# Appliance seat launcher

Current seats use [VM-only containment](../adrs/adr-060-vm-only-seat-containment.md):
one disposable VM per user running the ordinary full TechVault lab. Signing,
authenticated access and physical-host/cross-seat isolation remain required.
Additional isolation and controlled egress between workloads inside a guest are
not promised; that work is tracked in #1127. The signed V2 boundary policy and
runtime inventory identify this contract explicitly.

The launcher uses restricted QEMU user networking: the guest cannot initiate
connections to the physical host, another seat, or the external network. Only
the declared host-to-guest port forwards remain available. The complete lab
runs from its bundled offline inputs; this restriction does not separate
workloads inside the VM.

Issue #824 adds the host-side lifecycle adapter for one disposable appliance
seat. It consumes the signed release, overlay, and launch contracts from
[Disposable Appliance Release](appliance-release.md) without introducing a
host-resident APTL runtime.

## Security boundary

The seat is the preferred path when AI agents will operate the range or when
multiple users share a physical host. Direct `aptl lab start` places the
intentionally vulnerable workloads, MCP tooling, and Docker-authorized control
components on the selected host Docker engine. A seat instead places that
rootful Docker daemon and the entire range inside a dedicated disposable VM;
only signed loopback port mappings and the restricted authenticated MCP
transport cross the VM boundary. Compromise of an ordinary lab container is
therefore contained by an additional KVM/QEMU boundary before it reaches the
physical host or another seat.

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

The physical host must satisfy the signed release `host_prerequisites` block:

- Linux with hardware virtualization (`/dev/kvm`)
- `qemu-img`, `qemu-system-x86_64`, and read-only OVMF UEFI firmware
- available CPU/RAM at or above the manifest minimums, host disk capacity at
  or above the signed minimum, and free disk at or above the signed peak-runtime
  ceiling
- No dependency on host Docker for seat operations

Trust anchors:

- `--release-public-key`: release manifest Ed25519 anchor
- `--qualification-public-key`: participant qualification attestation anchor

Each user who launches a seat needs read/write access to `/dev/kvm`. On the
usual Linux packaging this means membership in the `kvm` group followed by a
new login session. The launcher reports every failed host prerequisite in one
bounded error instead of stopping after the first missing resource or tool.
On Debian/Ubuntu hosts, install the complete host dependency set once with:

```bash
sudo apt-get install qemu-system-x86 qemu-utils ovmf
```

No shared `seat-state` directory is required. Each user's default seat state
is created privately below that user's own `$XDG_STATE_HOME` or home directory.

## Install and start

Install a selected qualified public release using independently provisioned
trust anchors:

```bash
aptl seat install \
  --tag v5.5.0 \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem
aptl seat start
```

`seat install` anonymously downloads the signed metadata and transport chunks,
authenticates the metadata before downloading the large artifacts, resumes and
reuses verified cache entries, reconstructs both canonical artifacts, verifies
the complete release, and only then publishes it to the launcher's state.
Downloaded keys are never trusted merely because they appear beside a release;
the two key arguments are the independently provisioned trust anchors.

`seat start` automatically selects distinct outer ports. When the signed
release requires host MCP access, it creates an owner-only Ed25519 transport
identity, enrolls the current user for that seat generation, and safely updates
the Claude and Codex project configurations in the current directory. Provider
authentication remains entirely user-owned and is neither read nor copied.

All lifecycle commands default to the current user's private seat root:
`$XDG_STATE_HOME/aptl/seat`, or `~/.local/state/aptl/seat` when
`XDG_STATE_HOME` is unset. The download cache similarly defaults to
`$XDG_CACHE_HOME/aptl/appliance`, or `~/.cache/aptl/appliance`. `--seat-root`
and the explicit release/key options remain available for managed deployments
and qualification runs.

## Directory layout

```text
~/.local/state/aptl/seat/
  seat-state.json
  vm.pid                    # PID + procfs start/executable identity
  launch/
    release/                 # verified release directory
    appliance-launch.json    # create-once launch projection
    release-public.pem       # public release anchor
    qualification-public.pem # public qualification anchor
  instances/
    seat-01.qcow2            # disposable overlay
    seat-01.state/           # guest-only overlay identity (host tracks path only)
```

## Supported operator flow

After `seat install`, the simplest path is `aptl seat start` without `--mapping`
and without a pre-existing staged record. The launcher selects distinct
loopback ports while holding a host-wide lock through QEMU's bind and
live-listener readback, then persists those mappings for restart.

To reserve operator-selected ports instead, stage a verified release with one
repeated typed mapping for every signed guest publication:

```bash
aptl seat stage \
  --seat-root /srv/aptl-seat \
  --seat-id seat-01 \
  --release-dir /srv/aptl-seat/launch/release \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem \
  --mapping participant,tcp,127.0.0.1,10443,127.0.0.1,443 \
  --mapping recovery,tcp,127.0.0.1,11443,127.0.0.1,9443
```

The six mapping fields are audience, protocol, outer address, outer port,
guest address, and fixed guest port.

Duplicate outer endpoints, incomplete mappings, and destinations absent from
the signed publication policy fail closed. A staged mapping cannot be changed
during start; reset creates a new generation.

Automatic selection, explicit endpoint handoff, and capacity admission are
serialized across launcher processes. Each QEMU seat publishes its signed CPU,
RAM, and disk reservation in
a fixed `fw_cfg` argument. Before launch, the allocator sums every visible APTL
QEMU reservation and rejects the new seat if the concurrent total would exceed
host capacity. This makes the two-seat path an admitted resource allocation,
not two independent minimum checks racing each other. The available-memory
check also preserves host headroom of at least 8 GiB or 10% of physical RAM,
whichever is greater. A seat is refused before QEMU launches if it would
consume that reserve; this protects the host SSH service and other workloads.

Start the seat VM and validate host exposure. Readiness is not inferred from a
live PID or listener: the tracked QEMU instance, real forbidden-reachability
probe, guest boot/daemon observation, and complete appliance boundary gate must
all agree for the current generation:

```bash
aptl seat start \
  --seat-id seat-01 \
  --release-dir /srv/aptl-seat/launch/release \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem \
  --seat-root /srv/aptl-seat
```

Open the participant kiosk browser (presentation only):

```bash
aptl seat open-kiosk
```

Inspect coarse health (no credentials):

```bash
aptl seat status
```

## Reset and recovery

Security reset destroys the overlay and recreates a fresh overlay from the
verified golden. It is not a reboot, logout, or in-guest repair.

```bash
aptl seat reset \
  --seat-root /srv/aptl-seat \
  --seat-id seat-01 \
  --release-dir /srv/aptl-seat/launch/release \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem
```

Instructor recovery performs reset then start:

```bash
aptl seat recover \
  --seat-root /srv/aptl-seat \
  --seat-id seat-01 \
  --release-dir /srv/aptl-seat/launch/release \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem
```

After a physical-host reboot, reconcile persisted seat metadata before reuse:

```bash
aptl seat reconcile
```

When reconciliation reports `host-reboot-detected` or `vm-not-running`, run
`recover` before returning the seat to a participant.

## Diagnostics

CLI failures emit bounded JSON with stable codes such as `no-kvm`, `low-disk`,
`corrupt-overlay`, `failed-readiness`, and boundary inventory codes. Raw
QEMU/libvirt stderr, guest logs, and credentials are never returned.

## Related documents

- [ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md)
- [Appliance boundary](../components/appliance-boundary.md)
- [Issue #824 preflight](../architecture/issue-824-kiosk-launcher-reset-recovery-preflight.md)

## Full-TechVault host access contract

Issue #868 supplies the canonical software inputs and
[restricted host MCP interface](host-mcp-access.md). The real VM integration in
#1022 must allocate separate guest and outer ports, observe their explicit
mapping, and refresh private access records only after live guest identity and
capture checks. Existing browser-only seat APIs do not infer a host-MCP mapping
from equal port numbers. A host-MCP-enabled signed policy without an explicit
observed mapping fails admission.

Claude Code and Codex run on the participant host with user-owned provider
authentication. They receive a dedicated transport key and role-scoped project
config; MCP and Docker authority stay inside the guest. Reset revokes all old
grants and changes the instance generation/host pin before publishing replacement
access. A kiosk is an optional presentation surface, not a local APTL dependency.
The #1022 release qualification invokes an actual read-only `kali_info` MCP call
through each installed native client and its generated configuration, recording
only the response digest and client version. It then invokes the clients against
the revoked surface and independently proves the stale transport itself fails.
Service credentials and provider state never leave the guest.
