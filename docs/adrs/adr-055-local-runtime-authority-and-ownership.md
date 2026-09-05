# ADR-055: Local Runtime Authority and Ownership

## Status

proposed

## Date

2026-09-05

## Context

A scenario can describe privileged behavior without being authorized to grant
it. The reviewed backend copies some container security settings directly into
Compose, grants powerful init privileges implicitly, binds requested names from
the host environment, and can reuse or replace a foreign same-name container.

Single-user operation still needs boundaries between workspaces, the host,
operator credentials, range participants, and evidence. Loopback publications
protect inbound exposure but do not establish these other boundaries.

## Proposed decision

An effective realization is the intersection of the authored requirements,
the evidenced backend capability profile, and operator-granted authority.
Admission rejects an exact unsupported or unauthorized requirement before
deployment mutation. An allowed open choice is selected before mutation and
recorded as a backend choice; it must not silently satisfy an exact requirement.

Operator policy owns grants for images/builds, installed executable plugins,
capabilities, namespaces, mounts, daemon operations, ports, egress, credentials,
and resource limits. A pack requests these authorities; it cannot grant them.
Keep this as a bounded local policy model using existing contracts, without
introducing an organizational policy service.

The explicit orchestration-authority support added by PR #959 is useful
admission and observation machinery. Preserve it, but require an independent
operator grant for host-root-equivalent daemon access. A holder with the raw
socket is trusted with that daemon; authored child-image and label declarations
do not restrict what it can create. A `soc` profile and absence of published
ports do not independently prove management-network separation. Qualify that
separation, workspace-scoped child ownership and failure cleanup before
including this authority in an adoption claim.

Every mutable native resource has a workspace/project identity and, where
needed, an attempt identity. Names alone do not establish ownership. Verify
ownership before reuse, replacement, copy, exec, attachment, observation, or
deletion; operate on verified native IDs and account for replacement races.
Foreign or uncertain state produces a diagnostic and zero destructive action.

Credential bindings require an operator-selected source and an explicit grant
to a pack/consumer. Ambient environment membership is not a grant. Authored
fixture values remain scenario content. Generated-secret dependencies stay
part of the admitted graph. Private files use the existing no-follow containment
utilities and restrictive permissions from their first byte.

Distinguish acquisition/build access from execution access. Out-of-world egress
is denied unless the selected profile grants it. Preserve admitted in-world
traffic. Keep participant interfaces away from operator APIs, daemon sockets,
model credentials and evaluator-only storage. A socket with broad daemon
authority is not a narrow broker merely because its mount is read-only.

Native Docker remains the normal solo-user delivery path, with the actual
Linux kernel or Docker VM boundary disclosed. A sealed VM seat is optional
for stronger participant delivery. Elevated systemd capability requirements
must be measured and minimized for each supported platform; this ADR does not
assume a private cgroup namespace or rootless mode works with every pack.

## Failure and recovery

The backend records what it created before proceeding to the next stage.
Failure, cancellation, interruption and restart produce an explicit state:
clean, cleanup pending, or residual resources with an owned retry path.
Evidence of failure is preserved without pretending the run was valid.
Unknown cleanup is not success and cannot authorize an automatic retry.

Rollback/reset promises name covered state. Stopping containers is not a
complete reset of volumes, detector state, child workloads or provider memory.
No cleanup path may delete an unrelated workspace's state.

## Existing ADR disposition

On acceptance, clarify ADR-025, ADR-028, ADR-029, ADR-030, ADR-031, ADR-034,
ADR-039, ADR-045, ADR-051 and ADR-053. Supersede only ADR-049's
developer-only restriction on ordinary solo local operation. Retain its
stronger opt-in participant delivery contract. This review does not rewrite
the historical record or claim that today's default is hardened.

## Acceptance evidence and owners

Real isolated-daemon tests must cover foreign resources, two same-named
workspaces, partial starts, repeated teardown, credential canaries, unsafe
links, egress bypasses and policy-installation failure. Required owners are
[#952](https://github.com/Brad-Edwards/aptl/issues/952),
[#955–#958](https://github.com/Brad-Edwards/aptl/milestone/33),
[#964](https://github.com/Brad-Edwards/aptl/issues/964),
[#965](https://github.com/Brad-Edwards/aptl/issues/965),
[#966](https://github.com/Brad-Edwards/aptl/issues/966) and
[#968](https://github.com/Brad-Edwards/aptl/issues/968).
LilRAE #6 selects the profile and LilRAE #9 proves lifecycle security.
