# ADR-060: VM-Only Seat Containment

## Status

accepted

Owner decision on issue #1022. Supersedes the requirement to deliver internal
security zones with the current appliance in ADR-049 and ADR-059. Their other
signing, disposable-seat, host-access and qualification contracts remain.

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

## Consequences

The existing lab can run without an additional internal network architecture.
Compromise inside a guest may affect other workloads, credentials and evidence
inside the same guest. Internal default-deny egress and trusted management-zone
separation are not promised. VM-only seats must not be advertised or qualified
as satisfying the deferred internal-security contract. Normal lab network
behavior remains; physical-host and cross-seat protections are not deferred.
