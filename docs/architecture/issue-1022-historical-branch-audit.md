# Issue #1022 historical branch audit

Assessment against `8f20007ce323`, including the uncommitted content-mode repair.
This is a source comparison, not a claim of successful VM qualification.

## Sources and disposition

| Source | Useful evidence | Current disposition |
| --- | --- | --- |
| `398-readme-arsenal-acceptances`, `558-paper-proof-aptl-demo`, `codex/update-readme-conference-acceptances`, `fix/blackhat-workshop-happy-path` | Conference/demo history | Tips already ancestors of the working branch; no missing patch to merge. |
| `validation/blackhat-onboarding` (`81b6db8d`) and individual certificate, port, seed, smoke, and capture-fix branches | Certificate network isolation; stable active-profile ports; truthful endpoint display; volume cleanup; seed idempotency and failure propagation | Current implementations retain these behaviors, sometimes in split modules. One concrete omission remains: existing Shuffle workflows are skipped instead of refreshing credentials and webhook metadata. |
| `fix/shuffle-thehive-case-body` (`4b4c49fb`) | Scalar, single-line case body; correct HTTP app `verify` parameter; reuse TheHive keys | Present. Preserve current exact-alert-ID correlation when repairing workflow refresh. |
| `fix/vendored-cert-tool-digest`, `fix/wazuh-cert-bind-mount-permissions` | Preserve pinned vendor bytes; non-root consumers must read bind-mounted certs | Present in certificate production. The same permission requirement was not applied to generated scenario content under first boot's `umask 077`. |
| `validate/dev812-fixes`, `fix/wazuh-stateful-rule-mounts` | Explicit custom rule, decoder, and integration mounts | Current pack authors these artifacts and destinations; generic content placement replaces the old service-specific override. Do not restore the retired override. |
| `workshop-docs`, `docs/workshop-emergency-rollout`, `docs/workshop-rollout-generic-capacity` | Full-stack walkthrough, real MCP operations, canary-first rollout, teardown | Emergency runbook is already present. Original full-stack teaching flow remains useful; current guided-profile walkthrough is not full-TechVault acceptance. |
| `819-sealed-appliance-delivery`, `822-enforce-appliance-network-boundary` | Appliance boundary and enforcement | Existing ADR/enforcement, not an alternative startup implementation. The #822 merge-base diff is empty. |
| `820-participant-lab-profile`, `821-complete-workbench` | Semantic MCP smoke and managed participant runtime | Current code retains/evolves the mechanisms. The reduced guided profile is not the full-TechVault appliance source (ADR-059). |
| `823-versioned-lab-appliance`, `824-kiosk-launcher-recovery` | Offline payload, first boot, signed release, disposable seat lifecycle | Current code extends these incumbents. Older code lacks the repaired disk growth, launch-share ordering, live readiness, multi-user state, and endpoint allocation. No rollback or wholesale import. |
| `825-hosted-backup-seats` / `origin/825-hosted-backup-seats` | July DCV/Caddy runbook and pinned source staging tools | Preserve as historical contingency, not proof of the August full stack or current seat delivery. Audit found root-owned mode-0600 port configuration sourced by `ubuntu`; correct its ownership. |
| `889-cortex-adr088-envpack` (`b97746a5`) | August AMI/fleet provisioning plus MISP/Redis/Shuffle, Suricata, Kali, certificate, seed, and endpoint repairs | MISP/Redis/Shuffle settings, cert SANs/ownership repair, native Cortex state and env-pack-aware validation are already implemented or superseded. Current pack carries Suricata rules/variables. Preserve provisioning sources as non-executable historical references; do not run their destructive cleanup or permissive capture workaround. |
| `889-cortex-index-initial-service-state` (`adf7b4fa`) | Earlier Cortex native-state implementation | Superseded by current service-index materialization/readback, including native product mapping. |
| `889-cortex-index-state` (`3462dee1`) | August 5 facilitator/handout/QA records; earlier service-materialization prototype | Preserve actual attack/detect/case/fix/retest evidence and use the functional checks. Do not copy manual network attachments, hardcoded workflow IDs, or prototype materializer. |

The August QA record reports a working SQL injection → Suricata/Wazuh →
Shuffle → TheHive flow, followed by successful patch/retest/reset. It also
explicitly records direct Compose startup after strict handoff failed, and
range-only repairs. This proves the workflow was achievable; it does not prove
today's unmodified package or sealed guest. Conversely, missing Git commit
ancestry does not prove a behavior is missing: several fixes landed with other
commit identities.

## Current gaps and evidence

1. **Generated content permissions:** failed guest's indexer/dashboard report
   permission denied for root-owned mode-0600 configuration. First boot uses
   `umask 077`; content placement previously inherited it. Explicit public
   content modes must retain owner-only handling for sensitive content and
   executable modes for scripts. Do not relax the first-boot umask globally.
2. **Cassandra resource drift:** legacy Compose supplies `MAX_HEAP_SIZE=512M`
   and `HEAP_NEWSIZE=128M`; current Cassandra implementation profile supplies
   neither. Failed guest used an 8 GiB heap. Restore the bounded backend choice
   through admitted runtime environment. This alone does not establish the
   cause of TheHive's Cassandra connection timeout; inspect that separately.
3. **Shuffle rerun drift:** current seed exits when its workflow exists, so it
   neither repairs stale credentials nor recreates missing webhook metadata.
   The onboarding branch contains the behavior to recover, but its old host
   ports, fixed IPs, and body representation must not replace current contracts.
4. **Undeclared dynamic startup:** failed guest acquired/started `tenzir-node`
   and attempted to publish 1514, conflicting with Wazuh. The pack declares
   only worker and HTTP-app spawn templates. Guest Orborus logs confirm that
   `SHUFFLE_AUTO_IMAGE_DOWNLOAD=false` skips worker downloads but not Tenzir.
   Legacy Compose also sets `SHUFFLE_SKIP_PIPELINES=true`, plus disabled
   statistics/log collection; the backend profile omitted those settings.
   Restore them, not a new port or download. Current startup policy already
   supplies the workspace-resolved `ORBORUS_CONTAINER_NAME` separately.
5. **Historical tools:** the July payload combines three pinned source commits
   for a reduced profile. The August tools assume a baked AMI, an `ubuntu`
   Docker/sudo account, account-specific cloud resources, and mutable runtime
   repairs. Their success is not permission to run them on the shared host.
6. **Platform policy incorrectly claims scenario resources:**
   `appliance/policy.py` selects `aptl-redteam`, `aptl-security`, and `aptl-dmz`
   as participant, management, and egress networks, with Kali, the SOC
   workstation, and Suricata as their anchors. Those workloads do not implement
   the corresponding platform services. The only crossing is SOC workstation
   to Suricata on TCP 3128. The boundary helper's `_platform_table()` then drops
   other traffic entering or leaving every selected bridge, including ordinary
   same-bridge application traffic and guest-host control traffic. TheHive to
   Cassandra is therefore denied by the generated policy. Existing guest logs
   show Cassandra listening on 9042 before TheHive's connection failures; this
   is not evidence that increasing the startup timeout will help. The stopped
   guest does not provide a fresh live firewall observation, so this source
   diagnosis must still be verified in the repaired guest.
7. **Authority-policy mismatch:** the canonical policy permits a Docker holder
   labeled as the SOC workstation, while the admitted full-pack authority is
   Orborus. The #949 exception already permits that exact graph-admitted,
   guest-local authority; removing Orborus or broadly allowing socket holders
   is not a repair. Preserve the admission and observe its exact holder.

## Boundary assessment and decision point

**Resolved by the owner:** VM-only containment; internal security review and
implementation move to #1127. ADR-060 records the change. The alternatives
below retain the audit rationale, not an unresolved request for direction.

This is not just a port exception. The first-boot script runs the control plane
on the guest host; it does not construct distinct platform zones/services.
`_start_boundary_anchor_services()` additionally requires each anchor to be a
scenario `aptl.node.address`. Replacing three selectors without implementing
their owners will fail startup; allowing intra-bridge traffic would retain the
false management/participant/egress classification.

The APP-1 preflight expressly separates platform-owned placement from
RAES-owned scenario topology. ADR-059 preserves this distinction and the
canonical full lab. The historical #822 live integration test constructs three
separate platform networks and purpose-built workloads; it does not boot the
canonical production policy. `test_appliance_policy.py` only asserts the current
selectors, so it positively locks in the incorrect mapping. These tests explain
why component coverage did not catch the production integration failure.

The implementation decision must therefore be explicit:

- Retaining APP-1/ADR-049 requires materializing the actual platform boundary,
  attaching real participant/management/egress services, and verifying both
  permitted management-to-lab operations and forbidden scenario-to-management
  access. Keep RAES-owned scenario networks and policy unchanged. Extend the
  existing deployment/compiler/observation owners, not a parallel firewall
  framework. This is materially larger than the startup repairs above.
- A VM-containment-only delivery contract would run the normal full lab inside
  each isolated guest, but is **not** the currently accepted inner-boundary
  contract. It requires an explicit security/scope decision and corresponding
  contract updates. It must not be implemented as an undocumented firewall
  bypass or described as passing APP-1.

No boundary relaxation, historical branch merge, new VM boot, or artifact
rebuild was performed during this audit. The failed overlay remains diagnostic
evidence, not a qualified release.

## Repair and verification sequence

1. Preserve the useful historical runbooks/tools with immutable provenance and
   an explicit non-production boundary. No branch merge/cherry-pick.
2. Batch the demonstrated content-mode, Cassandra, and seed-idempotency repairs
   in current owners. Resolve Tenzir behavior and the Cassandra timeout from
   existing guest evidence before another clean boot.
3. Add focused behavioral regressions: real pack → rendered service settings;
   content modes under restrictive umask; execute the seed with controlled
   service responses for fresh/rerun/error paths. Source-string assertions and
   mocked successful startup alone are insufficient.
4. Resolve the boundary decision above before further VM work. Then use the
   existing failed overlay only as a diagnostic testbed. Confirm the
   affected services and full attack-to-case path before rebuilding. Such a
   patched overlay is explicitly not release qualification evidence.
5. Rebuild a clean candidate from the repaired source, reuse unchanged acquired
   inputs, and prove one ordinary `aptl seat start` plus the repository's manual
   QA. Only after that passes proceed to remaining lifecycle/multi-seat and
   publication obligations. Full suites run in PR CI, not locally.

## Targeted repair evidence

The content-mode, Cassandra heap, Orborus pipeline-disable, and Shuffle
fresh/rerun/error regressions were observed failing before their respective
repairs. The real-pack Cassandra/Orborus rendering and startup-adapter selection
passed 24 targeted tests. The seed also now rejects HTTP-200 application-level
failures before publishing webhook metadata; both write operations were first
observed incorrectly succeeding. These are local software checks, not VM
qualification, end-to-end attack-to-case proof, or the full CI suite.
