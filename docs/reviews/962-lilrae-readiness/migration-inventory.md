# Migration Inventory

This is a proposed ownership cut at the review baseline. The
[tracked-file ledger](tracked-file-inventory.tsv) assigns every existing path
an owner category. A core candidate still needs behavioral and import review;
the ledger is not an instruction to copy its whole directory.

| Area | Baseline assessment | Migration action and acceptance |
| --- | --- | --- |
| `src/aptl/cli` | Useful operator entry points; lab, experiment, provider and seat commands share one distribution | Keep local doctor/lifecycle/evidence commands in LilRAE; make experience/seat/campaign commands optional. Test installed human and JSON routes |
| `core/lab.py` | 2,926 lines; admission through SOC retry, certificate generation, MCP build/config and evidence | #970: one typed lifecycle coordinator; externalize experience hooks and preserve failure behavior |
| `backends` | 83 files, 21,271 physical lines; RAES adapters and materialization/readback | Preserve public contract adapters and tested local effects. Remove private `raes._source` dependency and obsolete older-package fallback; qualify each manifest claim |
| `core/deployment` | Reusable Docker/remote mechanics, but state shared across mixins; both generated and static Compose routes | Keep one deployment authority, scoped resources and narrow operation protocols. Retire static paths only after pack parity; no speculative second driver |
| `core/runtime` | In-memory execution of a bounded workflow subset | Verify current RAES delegation/ownership and actual supported effects. Do not migrate a competing semantic model or advertise persistence it lacks |
| `core/archival`, `evidence_bundle`, `provenance`, run storage and correlation | Valuable integrity, loss and lineage machinery | Keep generic mechanisms; separate research policy and optional projections. Preserve legacy reader compatibility where required by user data |
| `core/experiment`, `core/execution` | Admission/bindings plus campaign and apparatus policy | Split: generic safe admission and evidence mechanisms remain; scientific/campaign policy becomes an extension. Core recovery must work without a campaign controller |
| `core/credentials`, private-file and redaction utilities | Useful tested control boundary, inconsistently used in new env writer | Reuse one private-state primitive; separate real credentials, authored fixtures and per-consumer grants. Test both success and denial paths |
| `core/soc_*`, endpoints, collectors, snapshot and continuity | Mix generic mechanism with named TechVault/SOC assumptions | Move target knowledge and research continuity policy into experience modules; preserve generic observation and capture contracts |
| `validation` | 37 files, 8,421 lines; generic verification alongside TechVault/research qualifications | Keep generic conformance/extension host; externalize answer keys and profile-specific live probes. Static no-start results remain explicitly static |
| `workbench` | 11 files; installed provider adapters, private homes, tool-limited decisions | Optional participant extension; generic safe process supervision is a backend primitive. Add real confinement before claiming provider sandboxing |
| `mcp` | Eight servers and a common library; most servers are configuration wrappers | Package with selected APTL experience. Validate arguments and authority at server boundary. Host process/daemon access is part of their trust model |
| `plugins` | Verifier and serving-interaction seams already implemented | Finish external installation, compatibility identity and real tests. Keep trusted entry points small; do not add another plugin manager |
| `api` / `web` | Useful authenticated local UI and sanitized rendering; incomplete scenario/API journeys | Optional operator UI consuming core service interfaces and acquired-pack projections. Preserve access controls; no public multi-user exposure claim |
| `appliance`, seat/workshop tooling | Substantial optional delivery/security implementation | Keep separate payload/qualification profile. Linux/KVM seat constraints are not the ordinary user's prerequisites |
| `containers`, `config`, `scenarios`, scripts | Target content, backend substrates, delivery and research artifacts coexist | Classify by declared owner. Packs own vulnerable apps and scenario state; backend owns safe substrate/containment; experience owns scenario MCPs and verification |
| `_asset_manifest.py`, `hatch_build.py` | Released wheel can initialize assets, but it bundles Compose, source, MCP/web and experience trees | Preserve no-checkout install benefit; replace broad backend bundling with released pack/plugin acquisition and a small core artifact |
| Tests and CI | Large regression base; most MCP wrapper packages have no local vitest suite; integration marker conflates filesystem/subprocess with live tests | Preserve behavior tests and add risk-driven boundary tests. Keep all consumer builds and actual transport tests; #969 owns the release evidence matrix |
| Docs, ADRs, requirement exports | Historical and current claims coexist; old ACES/APTL peer-backend framing remains | Preserve historical evidence and UIDs. Rewrite current navigation and ownership. Reconcile requirements before implementation; do not silently transition status |

## Safe retirement candidates

- Static TechVault Compose/profile lookup paths after equivalent acquired-pack
  behavior is qualified. A checked-in file's existence must not select a
  privileged alternate execution path indefinitely.
- Named SOC seeding/retry/configuration in the generic lifecycle once an
  admitted owner supplies it. #915 still governs removal of undeclared effects.
- Legacy manifest writers and manifest-version fallbacks that no supported
  released consumer needs. Keep necessary readers with a migration policy.
- Historical SDL tutorials presented as current guidance. Retain historical
  records under explicit version/context labels.
- Feature proposals that duplicate RAES semantics or organizational control
  planes, and the obsolete APTL-versus-LilRAE paired-backend premise.

## Extension rule

Before adding a generic interface, identify two real callers or one concrete
translation/security boundary. Before adding a backend capability, identify a
fully adopted scenario that needs it. Neither a future feature list nor a file
length threshold is sufficient reason for another abstraction.
