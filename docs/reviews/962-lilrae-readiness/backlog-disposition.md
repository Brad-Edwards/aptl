# Existing Issue Disposition

Snapshot: 88 open APTL issues at `f35f86ee3bcc41f0b918fd209a944bf91e83f659`, 2026-09-05. Every issue receives a disposition below. “Partly delivered” requires reconciliation against acceptance evidence; it does not authorize closure. This review does not merge or close existing feature PRs. Requirement UIDs and status are preserved. PR #959 subsequently merged upstream; see the [update](upstream-update.md).

The new remediation issues are #963–#970. Existing LilRAE #3/#4/#6/#8/#9/#10/#21/#22 remain canonical for migration, conformance, profile design, lifecycle, qualification and participant control. No duplicate migration epic is created.

## Keep: local safety

| Issue | Recommendation |
| --- | --- |
| [#958: State the isolation boundary users actually get; keep the sealed seat opt-in](https://github.com/Brad-Edwards/aptl/issues/958) | Clarify actual solo-user Docker/VM boundary now; stronger seat stays optional. ADR-055 supersedes the developer-only wording by a new decision, not history rewriting. |
| [#957: Kali can authenticate to the Wazuh manager API with checked-in default credentials](https://github.com/Brad-Edwards/aptl/issues/957) | Priority fix for real control credentials and red-to-management reachability. Preserve intentionally planted scenario credentials separately. |
| [#956: Gate pack-declared `privileged`, `security_opt`, and seccomp settings behind admission](https://github.com/Brad-Edwards/aptl/issues/956) | Priority admission gate for all privilege-bearing fields. Add operator grants rather than silently stripping exact requirements. |
| [#955: Reduce generic systemd substrate privilege: private cgroup namespace, seccomp profile, minimal capabilities](https://github.com/Brad-Edwards/aptl/issues/955) | Measure minimal systemd privileges per supported runtime; do not assume rootless/private cgroups preserve every scenario. |
| [#939: Implement fail-closed Kali capture session admission](https://github.com/Brad-Edwards/aptl/issues/939) | Keep fail-closed capture admission. Record missing capture as invalid/incomplete evidence, not a successful research run. |
| [#856: Make participant credential sourcing config-controlled and defensible](https://github.com/Brad-Edwards/aptl/issues/856) | Keep configured participant credential-source design. Coordinate with #965; this owns provider credentials, not arbitrary pack bindings. |
| [#491: DEP-006: Isolation Tier Selection](https://github.com/Brad-Edwards/aptl/issues/491) | Clarify into local agent/range isolation profiles and qualification, consuming LilRAE #6 and ADR-057. Avoid implementing every isolation tier. |
| [#456: SAF-004: MCP Command Filtering (Allowlist/Denylist, Rate Limiting)](https://github.com/Brad-Edwards/aptl/issues/456) | Clarify tool capabilities, rate/resource limits and broker authorization. Regex filtering is not shell containment. #967 owns argument validation. |
| [#455: SAF-003: Tiered Autonomy Levels](https://github.com/Brad-Edwards/aptl/issues/455) | Clarify as consumption of released participant-control/autonomy profiles. Supersede any APTL-private semantic hierarchy; LilRAE #6/#21/#22 own selection and proof. |
| [#435: DSL-007: Perform backend cleanup and rollback for scenarios (backend consumption)](https://github.com/Brad-Edwards/aptl/issues/435) | Keep backend cleanup/reset/rollback for the admitted profile. Pair #952/#964 with LilRAE #9; do not wait for a general campaign engine. |

## Keep: realization correctness

| Issue | Recommendation |
| --- | --- |
| [#949: Fix TechVault Orborus socket lowering and offline child-image preparation](https://github.com/Brad-Edwards/aptl/issues/949) | PR #959 merged after the snapshot. Preserve its generic authority and image/readback machinery; remaining local policy and workspace scope are tracked in #956/#964. See the update. |
| [#918: Do not ignore authored OS distribution or version during substrate selection](https://github.com/Brad-Edwards/aptl/issues/918) | Keep exact OS distribution/version rejection or faithful realization; selection by family alone is insufficient for an exact claim. |
| [#917: Stop exempting undeclared init capabilities and mounts from realization verification](https://github.com/Brad-Edwards/aptl/issues/917) | Keep undeclared init capability/mount readback fixes; coordinate #955 without exempting baseline excess. |
| [#916: Honor authored open and closed realization boundaries end to end](https://github.com/Brad-Edwards/aptl/issues/916) | Keep open/closed concern enforcement through admission, mutation and final readback; upstream blockers shown closed now need released-version verification. |
| [#915: Remove post-admission TechVault mutations that bypass the authored realization boundary](https://github.com/Brad-Edwards/aptl/issues/915) | Keep as the mutation ownership umbrella. Shrink it to the remaining effects; #950 already retired Shuffle post-realization mutation. |
| [#912: Retire the MISP and Redis post-realization mutation](https://github.com/Brad-Edwards/aptl/issues/912) | Keep MISP/Redis authored-state repair with env-packs #280; neither delete needed behavior nor retain silent fixups. |
| [#910: Wire the TheHive<->Cortex API key via a generated-secret env affordance](https://github.com/Brad-Edwards/aptl/issues/910) | Keep generated-secret dependency wiring with released RAES #1074 and pack declarations; a private env hack is not completion. |
| [#909: Remove undeclared universal runtime-limit injection](https://github.com/Brad-Edwards/aptl/issues/909) | Keep removal/replacement of blanket unlimits; host safety caps must be operator policy and disclosed, not silently authored scenario facts. |
| [#869: Restore full TechVault component implementations under dynamic realization](https://github.com/Brad-Edwards/aptl/issues/869) | Clarify to residual component-parity failures now that component realization exists. Reuse the ADR-051 parity ledger. |
| [#864: Restore default TechVault parity through dynamic RAES composition](https://github.com/Brad-Edwards/aptl/issues/864) | Retain as the full TechVault scenario-pack qualification umbrella; its full-stack default must not become the small product profile. |
| [#809: Restore Wazuh endpoint telemetry across composed TechVault nodes](https://github.com/Brad-Edwards/aptl/issues/809) | Keep end-to-end endpoint telemetry proof; enrollment or a running manager alone is insufficient. |
| [#668: mail profile: mailserver setup.sh is never auto-run, so it shuts down unseeded](https://github.com/Brad-Edwards/aptl/issues/668) | Keep only for an explicitly selected mail profile; move setup/content into its pack and qualify before advertising mail. |

## Keep: acquired packs and migration

| Issue | Recommendation |
| --- | --- |
| [#934: docs: audit the APTL-to-LilRAE rename boundary](https://github.com/Brad-Edwards/aptl/issues/934) | Expand rename audit into explicit ownership/history/import/config/data migration inventory. Do not perform a mechanical rename before this boundary is agreed. |
| [#894: feat: consume published infrastructure kits through LilRAE](https://github.com/Brad-Edwards/aptl/issues/894) | Narrow to one released adopted kit-backed scenario at a time. Remove organizational tenancy language from personal-backend scope; all kit identifiers are not adoption prerequisites. |
| [#887: Bring bounded-participant-agency-techvault to the full realization contract](https://github.com/Brad-Edwards/aptl/issues/887) | Keep full declaration, exact source/runtime and live qualification for the advanced bounded-participant pack. |
| [#886: Create a scenario pack for techvault-observability-core](https://github.com/Brad-Edwards/aptl/issues/886) | Keep as an optional acquired-pack slice; qualify actual service behavior independently of catalog listing. |
| [#885: Create a scenario pack for techvault-enterprise-web](https://github.com/Brad-Edwards/aptl/issues/885) | Keep as an optional acquired-pack slice; qualify actual service behavior independently of catalog listing. |
| [#884: Create a scenario pack for techvault-defensive-min](https://github.com/Brad-Edwards/aptl/issues/884) | Keep as an optional acquired-pack slice; qualify actual service behavior independently of catalog listing. |
| [#883: Create a scenario pack for techvault-attacker-target](https://github.com/Brad-Edwards/aptl/issues/883) | Keep as an optional acquired-pack slice; qualify actual service behavior independently of catalog listing. |
| [#882: Realize kali-capture from a declared specification (asset-lock re-pin)](https://github.com/Brad-Edwards/aptl/issues/882) | Verify residual asset-lock/capture declaration gap against the released pack; preserve capture ownership and exact identities. |
| [#881: Where does scenario-specific efficiency work live (pre-built images, golden ranges)](https://github.com/Brad-Edwards/aptl/issues/881) | Clarify build/cache/golden-image ownership through pack identity and backend optimization. Qualify equivalent results; do not bypass declared materialization. |
| [#880: Move TechVault content out of APTL and consume it as a pack](https://github.com/Brad-Edwards/aptl/issues/880) | Physical pack move delivered: TechVault lives in OpenRAE/env-packs for now. Re-scope to residual APTL copies, packaging/startup coupling, uniform acquired-pack consumption and parity evidence. Do not repeat the move. |
| [#879: Extract TechVault semantic verification into a plugin](https://github.com/Brad-Edwards/aptl/issues/879) | Partly delivered: TechVault verifier package exists. Verify external packaging and qualified pack identity; do not build another plugin seam. |
| [#878: Define the scenario verification plugin seam and ship zero adapters in core](https://github.com/Brad-Edwards/aptl/issues/878) | Partly delivered: installed verification seam exists. Verify zero core adapters and failure semantics, then reconcile/close with evidence. |
| [#877: Separate structural parity from semantic verification in the live gate](https://github.com/Brad-Edwards/aptl/issues/877) | Keep structural-versus-semantic gate separation; some implementation exists. Reconcile against actual installed verifier and live proof. |
| [#605: Program: M7: Platform Hygiene & GRC](https://github.com/Brad-Edwards/aptl/issues/605) | Rewrite stale third-backend/reference-backend product claims; retain local safety and hygiene children. Use #962 roadmap instead of another program. |
| [#592: Clean APTL terminology for ACES-native scenario-pack references](https://github.com/Brad-Edwards/aptl/issues/592) | Clarify terminology under current RAES/OpenRAE direction and #934; preserve historical ACES records rather than blindly replacing text. |
| [#591: Split or migrate APTL capture assets that are scenario-pack authoring assets](https://github.com/Brad-Edwards/aptl/issues/591) | Keep capture-authoring asset ownership. Move reusable pack authoring inputs to their owning catalog/RAES tooling while preserving backend evidence capture. |

## Keep: release and adoption

| Issue | Recommendation |
| --- | --- |
| [#961: Flaky required check: macOS smoke fails non-deterministically on the participant qualification test](https://github.com/Brad-Edwards/aptl/issues/961) | Keep reported macOS qualification flake; verify deterministic root cause in the claimed matrix before release. |
| [#954: Quick-start docs, scenario catalog, and compose tests describe a range that no longer exists](https://github.com/Brad-Edwards/aptl/issues/954) | Keep user-doc/catalog/test truth-up against acquired released scenarios; list unsupported slices explicitly until qualified. |
| [#953: Env-pack admission plans twice per start and needs registry access for every image](https://github.com/Brad-Edwards/aptl/issues/953) | Partly superseded by #960: admit_raes_scenario now passes one admitted plan to start. Retain measured registry availability/cache/offline work and prove no duplicate planning before adding changes. |
| [#952: Failed `aptl lab start` leaves the whole range running with no teardown guidance](https://github.com/Brad-Edwards/aptl/issues/952) | Keep failed-start residual reporting and owned recovery; do not add unconditional teardown of potentially foreign state. |
| [#870: Prove packaged default TechVault parity on a clean local host](https://github.com/Brad-Edwards/aptl/issues/870) | Keep full TechVault installed-artifact semantic proof; depends on actual remaining parity, isolation and mutation fixes. |
| [#851: Earn the OpenSSF Best Practices badge, publish on Read the Docs, and rewrite the docs for users](https://github.com/Brad-Edwards/aptl/issues/851) | Split docs/usability from optional badge/site work. Actionable released docs and support are adoption work; a badge is not runtime evidence. |
| [#711: Track SonarCloud CE task failure on main push checks](https://github.com/Brad-Edwards/aptl/issues/711) | Keep operational Sonar task diagnosis if still reproducible; no weakening of required checks to mask it. |
| [#709: Reduce host_ports return count flagged by Sonar](https://github.com/Brad-Edwards/aptl/issues/709) | Low-priority measured code quality item. Revalidate the current finding before restructuring code to satisfy a stale metric. |
| [#685: Prove packaged full TechVault on macOS and Windows](https://github.com/Brad-Edwards/aptl/issues/685) | Keep advanced TechVault macOS/Windows proof; distinguish architecture, native host/VM and provider support. Do not generalize Linux tests. |

## Optional: workshop or participant profile

| Issue | Recommendation |
| --- | --- |
| [#888: feat: qualify a beginner-safe bounded participant walkthrough profile](https://github.com/Brad-Edwards/aptl/issues/888) | Keep as advanced deterministic walkthrough after #887/#880; no model credential needed by default and no dependency on paired-backend research. |
| [#868: Rebase participant workbench and optional appliance delivery on canonical TechVault](https://github.com/Brad-Edwards/aptl/issues/868) | Keep optional workbench/appliance parity; consume canonical TechVault, do not create a workshop-specific backend. |
| [#867: Make guided participant mode a hardening overlay on full TechVault](https://github.com/Brad-Edwards/aptl/issues/867) | Keep participant hardening as an explicit advanced overlay. It may not silently alter baseline scenario semantics. |
| [#826: Qualify canonical APTL for the 12-seat Black Hat Arsenal lab](https://github.com/Brad-Edwards/aptl/issues/826) | Keep event delivery outside solo adoption gate. Rehearse exact seat payload, resources and reset separately. |

## Optional: operator UI

| Issue | Recommendation |
| --- | --- |
| [#604: Program: M6: Local Operator Web GUI v1](https://github.com/Brad-Edwards/aptl/issues/604) | Keep local operator GUI program. Update stale language ownership; no hosted console or mandatory tiny UI dependency. |
| [#541: UI-008: Implement the APTL web GUI](https://github.com/Brad-Edwards/aptl/issues/541) | Reconcile against existing Svelte/FastAPI implementation; retain missing user behavior only, not a new GUI rewrite. |
| [#475: OBS-004: Real-Time Observability Dashboard During Scenarios](https://github.com/Brad-Edwards/aptl/issues/475) | Optional live observability surface after reliable lifecycle/evidence. No new parallel event/state engine. |
| [#421: DET-003: Live SIEM Query Execution from Web UI](https://github.com/Brad-Edwards/aptl/issues/421) | Optional authenticated SIEM query UI for a selected TechVault integration; retain request/response bounds and target-scoped credentials. |

## Optional: research extension

| Issue | Recommendation |
| --- | --- |
| [#753: EXP-011: Apparatus readiness and validity gate](https://github.com/Brad-Edwards/aptl/issues/753) | Keep apparatus validity gate for research profiles. Reuse lifecycle/native/security checks; do not block deterministic tiny use on scientific apparatus breadth. |
| [#603: Program and architecture: M5: ACES-conformant research apparatus](https://github.com/Brad-Edwards/aptl/issues/603) | Re-scope to an optional research apparatus within the same renamed product, consuming RAES contracts; shared lifecycle code stores evidence but does not own scientific policy. |
| [#499: SIM-004: Campaign pause, resume, and controlled re-execution](https://github.com/Brad-Edwards/aptl/issues/499) | Keep campaign pause/resume after durable journal #437. Mid-trial checkpoint requires an exact supported state envelope. |
| [#496: REP-006: Comparable precondition inspection between runs](https://github.com/Brad-Edwards/aptl/issues/496) | Keep comparability inspection over sealed evidence only; avoid inferred replay equivalence or analysis claims. |
| [#469: DEP-007: Experiment resource budgets and enforcement](https://github.com/Brad-Edwards/aptl/issues/469) | Keep bounded campaign budgets. Basic single-run safety limits belong in core and must not wait for this campaign feature. |
| [#463: AGT-005: Autonomous Objective Pursuit](https://github.com/Brad-Edwards/aptl/issues/463) | Defer autonomous objective-pursuit breadth to an adopted research profile; not a generic backend requirement. |
| [#461: SIM-005: Pacing Control](https://github.com/Brad-Edwards/aptl/issues/461) | Defer pacing until exact time-domain semantics and a scenario require it. |
| [#459: SCE-006: Isolated batch trial scheduling](https://github.com/Brad-Edwards/aptl/issues/459) | Keep serial trial scheduling first; parallelism requires proven workspace/name/network/resource isolation. Not a solo quickstart dependency. |
| [#450: ORC-004: Agent-to-Agent Communication and Shared Context](https://github.com/Brad-Edwards/aptl/issues/450) | Defer shared context/communication until scenario-led portable requirements and separation tests exist. |
| [#440: EXP-004: Provider-neutral participant and resource usage metering](https://github.com/Brad-Edwards/aptl/issues/440) | Keep provider-neutral usage/evidence extension; no provider billing or credential discovery in core. |
| [#437: EXP-001: Durable experiment execution and fault recovery](https://github.com/Brad-Edwards/aptl/issues/437) | Keep durable campaign journal outside tiny core. Core crash-safe lifecycle is required independently. |
| [#425: AGT-003: Persistent Cross-Session Agent Memory](https://github.com/Brad-Edwards/aptl/issues/425) | Defer persistent agent memory until an adopted scenario requires released semantics, reset/lifetime and leakage proof. |
| [#420: AGT-002 - ACES-Aligned Multi-Agent Coordination](https://github.com/Brad-Edwards/aptl/issues/420) | Defer broad multi-agent coordination; consume RAES contracts and require a concrete adopted scenario. |
| [#419: AGT-001 - ACES-Aligned Agent Orchestration Layer](https://github.com/Brad-Edwards/aptl/issues/419) | Re-scope to optional participant integration over RAES in the renamed product. Retire any plan to create a second APTL agent runtime. |

## Defer: scenario-led capability expansion

| Issue | Recommendation |
| --- | --- |
| [#497: RNG-004: Multi-node realization of AD forest topologies (backend capability)](https://github.com/Brad-Edwards/aptl/issues/497) | Advanced AD forest pack requirement only; do not build a general forest orchestrator before adoption forces it. |
| [#479: REP-005: Environment seeding mechanism (backend capability)](https://github.com/Brad-Edwards/aptl/issues/479) | Reconcile existing content/account/materializer mechanisms; add only missing seed effects exposed by a released scenario. |
| [#478: REP-004: Traffic generation engine (backend capability)](https://github.com/Brad-Edwards/aptl/issues/478) | Optional traffic-generation plugin/pack; specify required fidelity and observed effects before adding an engine. |
| [#473: INT-001: CALDERA integration capability (backend)](https://github.com/Brad-Edwards/aptl/issues/473) | Optional CALDERA scenario integration; keep its client, data, and policies outside shared lifecycle code. |
| [#471: DSL-006: Consume CACAO/Attack Flow-aligned scenario schemas (backend consumption)](https://github.com/Brad-Edwards/aptl/issues/471) | Consume published RAES/schema interoperability only when an adopted pack needs it; no local semantics implementation. |
| [#454: RNG-005: C2 framework realization capability (backend)](https://github.com/Brad-Edwards/aptl/issues/454) | Optional C2 scenario integration under explicit containment, not a default backend capability. |
| [#453: RNG-003: Snapshot/Restore for Mid-Scenario Checkpointing](https://github.com/Brad-Edwards/aptl/issues/453) | Defer general mid-scenario snapshots; ordinary reset/teardown remains mandatory and is not a snapshot claim. |
| [#445: INT-002: Atomic Red Team import pipeline (backend)](https://github.com/Brad-Edwards/aptl/issues/445) | Move Atomic Red Team parsing/conversion to pack authoring ownership; keep only qualified execution of released packs here. |
| [#436: DSL-009: Drive simulated user behavior profiles in realized ranges (backend realization)](https://github.com/Brad-Edwards/aptl/issues/436) | Optional behavior-profile realization driven by adopted portable declarations. |
| [#434: DSL-005: Evaluate scenario pre/post-conditions and assertions against realized state (backend consumption)](https://github.com/Brad-Edwards/aptl/issues/434) | Reconcile current evaluator/readback support and add missing predicate shapes only when scenario-required. |
| [#433: DSL-004: Verify composed RAES scenarios across APTL execution paths](https://github.com/Brad-Edwards/aptl/issues/433) | Keep concrete composed-pack integration and immutable closure tests; no new composition engine. |
| [#216: Integrate CAPEv2 for dynamic malware analysis](https://github.com/Brad-Edwards/aptl/issues/216) | Defer CAPEv2 as a malware-analysis integration with its own VM/detonation qualification. It is not the agent sandbox solution. |
| [#5: Pre-seeded SIEM data loading capability (backend)](https://github.com/Brad-Edwards/aptl/issues/5) | Supersede obsolete qRadar/Splunk adoption scope under ADR-002. Future preseeded datasets belong to a concrete selected SIEM pack/plugin. |

## Route or retire: outside personal backend

| Issue | Recommendation |
| --- | --- |
| [#601: Program: M3: Conformant-Backend Demonstration](https://github.com/Brad-Edwards/aptl/issues/601) | Supersede APTL-versus-LilRAE independent-backend demonstration framing. Use Hub #15 and LilRAE #11. |
| [#558: research: produce the APTL side of paired-backend participant evidence](https://github.com/Brad-Edwards/aptl/issues/558) | Supersede the n=2 APTL-versus-LilRAE premise. Retain reusable research evidence; paired backend research belongs to LilRAE #11 with BigRAE. |
| [#490: DEP-005: Federation Support](https://github.com/Brad-Edwards/aptl/issues/490) | Route organizational federation to BigRAE/Hub or defer a narrowly justified portable seam; not solo adoption work. |
| [#486: SIM-003: Abstract Simulation Model](https://github.com/Brad-Edwards/aptl/issues/486) | Route abstract simulation meaning to RAES/research; avoid a competing model inside LilRAE. |
| [#480: RNG-002: Multi-Node and Cloud Deployment](https://github.com/Brad-Edwards/aptl/issues/480) | Split local multi-node scenario support from hosted/cloud fleet deployment. Local multi-node already exists; cloud scope belongs elsewhere. |
| [#451: REP-002: Infrastructure-as-Code Abstraction](https://github.com/Brad-Edwards/aptl/issues/451) | Reconcile existing DeploymentBackend abstraction. Retire speculative abstraction-for-abstraction work; a new driver requires a real profile. |
