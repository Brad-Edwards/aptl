# APTL Readiness for LilRAE

Review: [#962](https://github.com/Brad-Edwards/aptl/issues/962).
Baseline: `dev` at `f35f86ee3bcc41f0b918fd209a944bf91e83f659`.
Assessment date: 2026-09-05. Initial findings refer to that commit. The
[upstream update](upstream-update.md) assesses PR #959 at `65390508`, merged
into the review branch before final verification.

## Assessment

APTL is the working name of the product being renamed to LilRAE. It has useful
contract, observation, and evidence machinery, but it is not yet a reliably
bounded, independently qualified personal range that should be recommended to
other users without its current development limitations. Preserve the working
mechanisms and history. Fix the authority and lifecycle gaps, then separate
shared lifecycle behavior from scenario-pack integrations and research policy.
A rename, a wholesale rewrite, or additional generic abstraction would not
resolve the principal problems.

The intended identity is clear: APTL and LilRAE are one product across a
rename, not separate products, layers, or user experiences.
TechVault is a scenario pack. It is selected by that product, and its
integrations remain pack-specific capabilities, not a retained APTL layer. The
small quickstart is a bounded profile on the same product, and RAES owns
portable semantics and conformance.
Technical extraction and release work remains, but it must not recreate a
product-to-product migration model.

**TechVault content has already moved to
[OpenRAE/env-packs/packs/techvault](https://github.com/OpenRAE/env-packs/tree/main/packs/techvault)
for now.** The pack includes its SDL, assets, seeded content and artifact
manifest. Its README records `built` maturity, with golden-range proof still
outstanding. This plan consumes that existing pack. #880 covers residual APTL
copies, packaging/startup coupling and consumer parity; it does not schedule
the physical pack move again or choose a new permanent home. The APTL-to-LilRAE
change is identity continuity plus technical decoupling, not a migration
between products or another runtime layer around TechVault.

## Evidence and coverage

The review inventoried all **1,467 tracked paths** at baseline, traced the main
lifecycle, RAES adapters, native realization/readback, participant launch, MCP
dispatch, API/UI, evidence, plugin, packaging, container and CI boundaries,
and reviewed the **88 initially open issues** and **54 existing ADRs**. The
Python application has **398 files and 88,587 physical lines**, including
comments/docstrings; tests contain 93,278 physical lines across 256 Python
files. Size is context, not a defect count.

At `dev` commit `d48d2b7e`, the repository contains **1,505 tracked paths**.
The tracked-file ledger now reconciles the **38** additions since the original
baseline; no baseline path had disappeared at that commit. The three new #934
artifacts bring the final delivery inventory to **1,508 paths**. The
complementary [identity-disposition ledger](identity-disposition.tsv) records
independently versioned identity surfaces without treating every occurrence as
a product boundary.

This is a repository-wide architecture and risk review with targeted code
inspection and probes. It is not a claim that every line was manually audited,
nor a penetration test or exhaustive dependency-vulnerability assessment.

| Verification | Result and limit |
| --- | --- |
| `pre-commit run --all-files` | Passed all configured hooks, including Python, common/red MCP and web tests |
| `uv run pytest -n auto tests/test_techvault_static_gate.py -m integration` | 2 passed at both source baselines (42.61 / 58.30 seconds); no-start/static evidence |
| Documentation | Strict MkDocs build and direct Vale check passed; revision-date metadata warnings recorded |
| Harmless process probes | Confirmed deadline overrun and surviving descendant; synthetic descendant cleaned up |
| Fake-daemon and temporary-file probes | Confirmed foreign-container reuse/removal requests, ambient canary binding and symlink-following env write; no daemon or real credentials used |
| CI and dev protection inspection | Required contexts inspected through GitHub API; advisory versus required distinction recorded |
| Clean-host/live range | Not performed; no Docker resources, firewall state or volumes changed during this review |
| External participant/model execution | Not performed; local CLI help/version and source inspected only |

The passing suite coexists with the confirmed bugs. That points to missing
boundary/failure tests rather than a need for more tests that mirror helpers.
Existing live artifacts remain evidence for their recorded versions only.
PR #959 was open at the initial snapshot and subsequently merged upstream.
Its additional authority controls and remaining limits are covered in the
update. The four dependency PRs open at the snapshot are not baseline code.

## Findings, in priority order

Priority concerns readiness for affected profiles; it is not a CVSS score.
“Confirmed” means the described code path was reproduced with a safe probe,
not that a live host exploit was attempted.

| ID | Priority / confidence | Finding, implication and owner |
| --- | --- | --- |
| F01 | High / source-confirmed, existing issue | Pack-controlled `privileged` and `security_opt` reach Compose; systemd adds powerful capabilities, host cgroups and unconfined seccomp. A capability allowlist alone does not close this boundary. [#956](https://github.com/Brad-Edwards/aptl/issues/956), [#955](https://github.com/Brad-Edwards/aptl/issues/955), [#917](https://github.com/Brad-Edwards/aptl/issues/917) |
| F02 | High / confirmed canary | Authored environment names select from `os.environ` without an independent pack/consumer grant. Ambient values also override authored fixtures. [#965](https://github.com/Brad-Edwards/aptl/issues/965) |
| F03 | High / confirmed temporary-file probe | Generated env files follow symlinks, truncate the target and do not repair an existing permissive mode. Reuse the established no-follow file boundary. [#966](https://github.com/Brad-Edwards/aptl/issues/966) |
| F04 | High / confirmed fake-daemon probe | A same-name, same-image foreign container is accepted; a stopped/wrong-image foreign container receives a forced-removal request. Naming is not project-scoped despite the helper's description. [#964](https://github.com/Brad-Edwards/aptl/issues/964) |
| F05 | High / confirmed process probe | A 0.2-second timeout returned success after 2.021 seconds because stdin delivery precedes the deadline. Successful parent exit leaves descendants running. [#963](https://github.com/Brad-Edwards/aptl/issues/963) |
| F06 | High / source and existing live report | Ordinary local operation lacks the appliance's enforced egress boundary. The existing #957 report demonstrates Kali access to Wazuh management using public credentials. Loopback host bindings do not isolate internal management paths. [#968](https://github.com/Brad-Edwards/aptl/issues/968), [#957](https://github.com/Brad-Edwards/aptl/issues/957), [#958](https://github.com/Brad-Edwards/aptl/issues/958) |
| F07 | High / source-confirmed, existing issues | Failed startup returns without transactional cleanup; post-admission mutations and implicit state weaken exact realization claims. [#952](https://github.com/Brad-Edwards/aptl/issues/952), [#915](https://github.com/Brad-Edwards/aptl/issues/915), [#916](https://github.com/Brad-Edwards/aptl/issues/916), [#909](https://github.com/Brad-Edwards/aptl/issues/909), [#918](https://github.com/Brad-Edwards/aptl/issues/918) |
| F08 | Medium / source-confirmed | Low-level MCP SDK request validation accepts unknown argument values; APTL dispatch does not validate each advertised tool schema despite comments claiming it does. [#967](https://github.com/Brad-Edwards/aptl/issues/967); capability/rate policy stays in [#456](https://github.com/Brad-Edwards/aptl/issues/456) |
| F09 | High / evidence gap | Manifest/schema conformance is not proof of live effect, rollback, containment or a usable range. Advisory checks and unchecked protection settings weaken adoption confidence. [#969](https://github.com/Brad-Edwards/aptl/issues/969), [LilRAE #4](https://github.com/OpenRAE/lilrae/issues/4), [#870](https://github.com/Brad-Edwards/aptl/issues/870) |
| F10 | Medium / source-confirmed | `lab.py` is a 2,926-line coordinator coupling generic lifecycle to SOC and provider setup. Whole-tree asset bundling and static compatibility paths preserve the same coupling at installation. [#970](https://github.com/Brad-Edwards/aptl/issues/970), [#934](https://github.com/Brad-Edwards/aptl/issues/934), [#880](https://github.com/Brad-Edwards/aptl/issues/880) |

Source anchors: [init authority](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/src/aptl/backends/raes_base_substrate.py),
[Compose lowering](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/src/aptl/core/deployment/_compose_node_generation.py),
[container ownership and env writes](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/src/aptl/core/deployment/_compose_base_substrate.py),
[process runner](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/src/aptl/workbench/process.py),
[lifecycle](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/src/aptl/core/lab.py),
[MCP dispatch](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/mcp/aptl-mcp-common/src/server.ts),
[manifest](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/src/aptl/backends/raes_manifest.py),
[static backend](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/src/aptl/validation/_gate_no_start_backend.py),
[checks](https://github.com/Brad-Edwards/aptl/blob/f35f86ee3bcc41f0b918fd209a944bf91e83f659/.github/workflows/checks.yml).
Reproduction scripts and results are in [evidence](evidence/README.md).

## What to preserve and what to simplify

The RAES handoff uses the published RuntimeManager rather than inventing a
parallel top-level lifecycle. Component realization, artifact identities and
native readback already form a useful foundation. The environment-pack path
passes an admitted plan into startup; the double-planning premise of #953 is
partly overtaken by #960. Verify the remaining availability/cache issue.

Private-state helpers, redaction, archive sealing, provenance and fail-closed
verifier discovery deserve preservation. The local web surface has bearer
authentication, Host/CSRF defenses, a two-factor browser session, terminal
tickets and SSH host-key verification. Markdown uses DOMPurify. Intentionally
vulnerable application code belongs in target packs; it should not be “fixed”
as if it were operator-facing application code.

The control flow remains difficult to reason about across mutable lifecycle
context and mixins. Per-function C901/ESLint gates do not measure that coupling.
Do not respond by creating dozens of tiny forwarding files. Separate
lifecycle, admission, realization, observation, and scenario-selected hooks
with explicit inputs, outputs, failure states and ownership. There are 83 broad
Python exception handlers in the static inventory; inspect safety-critical
cases individually rather than treating all defensive exception mapping as a
defect.

The manifest includes scenario/research features such as `x-paper:wazuh-evidence`.
The verifier and serving-interaction plugins already exist, so #878/#879 are
reconciliation and packaging work rather than greenfield architecture. The
verifier's empty content-digest restriction needs an explicit compatibility
policy before independent release. Entry-point discovery executes trusted
installed code; it is not a plugin sandbox.

The existing workflow engine can remain only as execution of published RAES
contracts with precise evidence for the supported subset. Evaluate it against
current upstream ownership while migrating; do not infer it is redundant merely
because it is an engine. Preserve safe archive compatibility where users have
data, with an explicit retirement policy for legacy writers and paths.

## Viable adoption path

1. **Establish safe local authority.** Repair confirmed defects and existing
   isolation issues. Give each workspace owned resources, bounded processes,
   explicit grants, enforceable egress and reliable failure recovery.
2. **Qualify a bounded capability envelope.** Maintain one claim ledger under
   LilRAE #6/#4. A fully adopted scenario requires exact acquisition, meaningful
   behavior, readback, negative cases and cleanup. Add capability only when the
   next adopted scenario requires it.
3. **Decouple the product with history.** Use #934/#970 and LilRAE #3 while
   preserving that APTL and LilRAE are the same product. A small install must
   not import or install TechVault/SOC/research/provider machinery. Advanced
   functionality remains available through selected packs/plugins.
4. **Prove released journeys.** LilRAE #10 and Hub #3 own the tiny useful result,
   one changed input and teardown. #870/#685 own the separate full TechVault
   parity proof. Record cold-download and warm-run timing honestly.

Preparation can run in parallel where inputs permit. GitHub blocking edges
represent prerequisites for delivery/qualification, not a prohibition on
writing tests or preparing dependent work. The review does not make the tiny
profile wait for all TechVault slices, campaign features or BigRAE research.

The first adoption target should use the concrete shape already specified by
[Hub #12](https://github.com/OpenRAE/hub/issues/12): one service, one dependency,
one observable failure and one bounded recovery input. Prove acquire, check,
plan, realize, independent readiness, changed result, reset and teardown from
released artifacts. The ten-minute first-result target includes acquisition;
record the reference host and resource envelope. This is a useful first
materialization envelope, not a promise that the current APTL default meets it.

## Deliverables and roadmap

- [Ownership and rename inventory](migration-inventory.md), with an owner category for
  [every tracked path](tracked-file-inventory.tsv).
- [Identity disposition](identity-disposition.tsv), covering technical names,
  compatibility boundaries, retirement evidence, and coordination owners.
- [Disposition of all 88 existing issues](backlog-disposition.md).
- [Disposition of all 54 existing ADRs](adr-disposition.md), plus proposed
  ADR-054 through ADR-058. None is marked accepted by this review.
- [Agent sandboxing assessment](agent-sandboxing.md).
- [Milestones and dependency graph](delivery-plan.md).
- [Changes that landed during review](upstream-update.md).

The two new milestones cover technical decoupling and release qualification. Existing
local-isolation and released-quickstart milestones remain useful. Obsolete
APTL-versus-LilRAE research framing should be superseded; cloud federation,
general simulation, broad kit support, CAPEv2 and speculative agent features
need a concrete owner and adopted scenario before becoming implementation work.
