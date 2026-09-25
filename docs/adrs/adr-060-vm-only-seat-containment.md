# ADR-060: VM-Only Seat Containment

## Status

accepted

Owner decision on issue #1022. Supersedes the requirement to deliver internal
security zones with the current appliance in ADR-049 and ADR-059. Their disposable-seat, host-access and qualification contracts remain.
The owner decision on #1162 replaces their bespoke signed-release transport
with GHCR artifacts authenticated by Cosign, as described below.

## Date

2026-09-20

## Context

The immediate product is the existing full TechVault lab running with rootful
Docker inside one disposable VM per user. The production appliance policy
incorrectly selected scenario networks and workloads as platform security
zones, blocking ordinary lab traffic. Implementing additional internal security
domains is not necessary to deliver that product and is explicitly deferred.

## Decision

The VM is the seat containment boundary. Keep the ordinary admitted TechVault
topology, services, scenario ACLs and workflow unchanged. Do not add or claim
participant/management/egress isolation inside that guest. Review and implement
internal security separately in [issue #1127](https://github.com/Brad-Edwards/aptl/issues/1127),
including APP-1; it is not a completion gate for #1022.

The signed `aptl.appliance-boundary/v2` policy explicitly describes VM-only
containment and cannot contain inner-zone selectors, crossings, proxy policy
or a default-deny claim. V1 retains its original internal-zone validation;
changing containment requires new signed bytes, never an environment bypass.
Runtime inventories state which containment contract was observed and do not
manufacture internal firewall/probe evidence for a VM-only seat.

Retain verified artifacts and trust anchors, private per-user state, separate
guest Docker daemons and overlays, authenticated instance-specific readiness,
restricted seat-scoped MCP access, loopback host mappings, and physical-host /
cross-seat isolation. Guest-Docker operations continue through normal admitted
backend authority. Stop/reset affect only the owned VM. Release qualification
still requires actual lab behavior, lifecycle isolation and independent-machine
evidence; software tests are not that evidence.

## Image delivery and trust

Seat images are cut locally, independently of Python package releases. GHCR
stores one immutable OCI manifest binding the qcow2 disk and its launch config;
Cosign signs that manifest digest. The launcher verifies it against the public
key shipped with the CLI before acquiring executable bytes. An alternate
repository requires an independently supplied public key. Digests establish
integrity; the trusted signature establishes publisher identity. Neither is
proof of successful testing or reproducible provenance.

The default channel is `ghcr.io/brad-edwards/aptl-seat:latest`. First acquisition
requires default-no consent or explicit `--yes`. A verified local selection is
sticky and boots without registry access. Confirmed updates verify and admit the
replacement before resetting the stopped seat and retiring its superseded cache
entry. Each overlay retains its own immutable base so another seat's update
cannot remove its backing file. Mutable tags never authorize an automatic reset.

Cosign verification records are private local admission receipts bound to the
manifest, disk, config, repository and public-key fingerprint. They permit
offline reuse under the same trusted key; they are not portable attestations.
Key rotation requires independently updating trust and re-verifying the image.
The private signing key stays on the publishing machine, outside source and
image payloads; only its public counterpart is distributed.

Publication follows real VM qualification, cleanup, clean-range startup and
shutdown against the exact image. Evidence identifies source and artifact
hashes and distinguishes automated tests from observed range behavior. An
immutable signed candidate must work anonymously before an optional, bounded
`:latest` promotion. Package publication and back-merges do not wait for image
builds or registry promotion.

## Consequences

The existing lab can run without an additional internal network architecture.
Compromise inside a guest may affect other workloads, credentials and evidence
inside the same guest. Internal default-deny egress and trusted management-zone
separation are not promised. VM-only seats must not be advertised or qualified
as satisfying the deferred internal-security contract. Normal lab network
behavior remains; physical-host and cross-seat protections are not deferred.


Each staged generation retains its verified disk, configuration, and publisher
trust record under its private seat root. Shared registry-reference selections
only choose defaults for new seats and explicit updates; retiring a shared cache
entry cannot invalidate another seat's offline launch. Browser credentials are
passed through an owner-private bootstrap file, never process arguments or
printed launch plans.
