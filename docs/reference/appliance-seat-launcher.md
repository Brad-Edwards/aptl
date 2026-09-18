# Appliance seat launcher

Issue #824 adds the host-side lifecycle adapter for one disposable appliance
seat. It consumes the signed release, overlay, and launch contracts from
[Disposable Appliance Release](appliance-release.md) without introducing a
host-resident APTL runtime.

## Prerequisites

The physical host must satisfy the signed release `host_prerequisites` block:

- Linux with hardware virtualization (`/dev/kvm`)
- `qemu-img` and `qemu-system-x86_64`
- RAM and free disk at or above the manifest minimums
- No dependency on host Docker for seat operations

Trust anchors:

- `--release-public-key`: release manifest Ed25519 anchor
- `--qualification-public-key`: participant qualification attestation anchor

## Directory layout

```text
/srv/aptl-seat/
  seat-state.json
  vm.pid
  launch/
    release/                 # verified release directory
    appliance-launch.json    # create-once launch projection
  instances/
    seat-01.qcow2            # disposable overlay
    seat-01.state/           # guest-only overlay identity (host tracks path only)
```

## Supported operator flow

Stage a verified release:

```bash
aptl seat stage \
  --seat-root /srv/aptl-seat \
  --seat-id seat-01 \
  --release-dir /srv/aptl-seat/launch/release \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem
```

Start the seat VM and validate host exposure:

```bash
aptl seat start \
  --seat-root /srv/aptl-seat \
  --seat-id seat-01 \
  --release-dir /srv/aptl-seat/launch/release \
  --release-public-key /etc/aptl/trust/release-public.pem \
  --qualification-public-key /etc/aptl/trust/qualification-public.pem
```

Open the participant kiosk browser (presentation only):

```bash
aptl seat open-kiosk
```

Inspect coarse health (no credentials):

```bash
aptl seat status --seat-root /srv/aptl-seat
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
aptl seat reconcile --seat-root /srv/aptl-seat
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
