# Changes That Landed During Review

The initial stocktake uses `f35f86ee3bcc41f0b918fd209a944bf91e83f659`.
During the review, [PR #959](https://github.com/Brad-Edwards/aptl/pull/959)
merged to `dev` as `65390508`. The issue branch incorporated that commit with
a normal merge. The initial tracked-file inventory and probe results remain
identified by their original baseline; they are not retroactively presented
as a different snapshot.

## What improved

The update adds explicit RAES orchestration-authority admission, carried
deployment decisions, exact local socket/daemon binding, child-image closure
preparation and post-start observation. It validates the effective Compose
socket footprint, rejects endpoint overrides, observes exact image identities
and child counts, and attempts bounded child termination. These are useful
generic backend mechanisms to preserve in the migration.

Sources at the updated commit:

- [Authority admission](https://github.com/Brad-Edwards/aptl/blob/65390508/src/aptl/backends/raes_runtime_orchestration.py)
- [Effective model validation](https://github.com/Brad-Edwards/aptl/blob/65390508/src/aptl/core/deployment/_compose_runtime_orchestration.py)
- [Daemon binding](https://github.com/Brad-Edwards/aptl/blob/65390508/src/aptl/core/deployment/_docker_endpoint_binding.py)
- [Runtime observation](https://github.com/Brad-Edwards/aptl/blob/65390508/src/aptl/core/deployment/_compose_runtime_observation.py)
- [Child lifecycle](https://github.com/Brad-Edwards/aptl/blob/65390508/src/aptl/core/deployment/_compose_child_lifecycle.py)

## Remaining adoption limits

These are source-review conclusions, not a live test of the new capability.

1. **Authority still needs operator policy.** The admission function consumes
   deployment nodes, requires a `soc` profile, no published participant service
   or port, and no joined network namespace. It does not consume an independent
   operator grant. Network membership and those shape checks do not prove
   separation from participant traffic. Extend #956's privilege admission work
   to cover this explicit host-root-equivalent authority.
2. **Raw Docker access trusts the holder.** The socket lets the holder create
   resources beyond the authored child closure. Child observations corroborate
   the selected image/label subset; they are not an enforcement boundary around
   a compromised holder. Use a narrowly authorized disposable daemon/guest, or
   a separately qualified broker, when that stronger guarantee is needed.
3. **Child correlation needs workspace ownership.** `_correlated_child_ids`
   searches the selected daemon by authored image and label. Labels are unique
   within one realization, but that is not uniqueness across workspaces or
   attempts. Observation and deadline termination must not select another
   workspace's child. Include this path in #964's ownership acceptance tests.
4. **Observation failure is not rollback.** Child observation and termination
   can return a failure with remaining live resources. #952 still needs a
   complete owned recovery path, including control holders and spawned children.
5. **Historical architecture changed too.** PR #959 narrows ADR-049's socket
   prohibition for a same-node, explicitly admitted authority. Proposed ADR-055
   preserves that mechanism while adding independent policy and clearly stated
   trust assumptions. It does not silently repeal the upstream change.

The source files responsible for the process, base-container reuse, ambient
credential binding and env-file defects were unchanged by PR #959. Its new
authority-specific privileged-container check does not establish a global
policy for every realization. Findings F01–F10 therefore remain actionable;
#949's implementation itself is no longer pending.

The final branch verification is recorded in the [evidence index](evidence/README.md).
Live orchestration behavior and clean-host qualification remain outstanding.
