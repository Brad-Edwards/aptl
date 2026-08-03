---
id: SCN-010
title: "ACES SDL as APTL's Canonical Scenario Authoring Surface"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-05-18T04:48:47.928455Z
updated_at: 2026-05-19T18:38:04.120446Z
---

# SCN-010 — ACES SDL as APTL's Canonical Scenario Authoring Surface

## Statement

APTL shall consume the external Agentic Cyber Environment System (ACES) SDL (sibling repository at ../aces-sdl) as its canonical scenario authoring surface. All authored scenarios shall be ACES SDL documents validated by the ACES reference parser, compiled through the ACES runtime model, and executed via an APTL-implemented ACES backend target. APTL shall not maintain a parallel in-tree scenario specification language. APTL's backend implementation shall publish a backend-manifest-v2 declaring conformance to a named ACES backend capability profile from contracts/profiles/backend/, with `provisioning-only` as the initial target, and shall pass the `aces conformance backend` suite for that profile. The legacy `aptl.core.sdl` and `scenarios/*.yaml` paths shall remain functional until the ACES-authored `techvault.sdl.yaml` scenario reaches capability parity with the existing scenario set (same node/service/vulnerability/feature surfaces, injects, scenario flow shapes, objectives, scoring outputs, and run-archive surfaces); once parity holds, the default scenario flips to the ACES TechVault, `scenarios/*.yaml` moves to `scenarios/archive/` as reference-only material, `aptl.core.sdl` is deleted, and Pydantic ScenarioDefinition models are deleted — all in a single cutover PR. This requirement supersedes DSL-001 and SCN-001 (both transitioned to DEPRECATED at cutover) and deprecates DSL-002 through DSL-009 at cutover. RTE-001's input source changes from APTL's in-tree DSL to the ACES RuntimeModel.

## Rationale

APTL and ACES are co-developed inside a single research agenda. ACES's core research claim is that the same authored scenario can be realized across multiple range backends; APTL is the first production-style backend that exercises the ACES contract surface end-to-end. Maintaining a parallel APTL-local SDL fragments authoring tools, drifts grammar versus ACES, and prevents cross-backend scenario comparison — collapsing the reproducibility claim the program rests on. Better-specified scenarios (typed ACES runtime model, planned reconciliation with explicit ordering and refresh dependencies, contract-validated runtime envelopes, OCI module distribution with lockfiles via `aces sdl resolve`/`verify-imports`/`publish`) directly support reproducibility of experimental runs across backends, time, and authors. Carrying two SDLs is also duplicate engineering: every DSL-002..DSL-009 feature is already on the ACES roadmap, and ACES has tooling APTL would otherwise rebuild in-tree. Adoption is structured as a two-phase migration (parallel ACES path during Phase A; single cutover PR for Phase B) so APTL is not broken during the transition. ADR-035 records the decision. The remaining work is not just to make TechVault trigger through ACES; APTL must implement a scenario-generic ACES backend interpreter/realizer for any scenario within APTL's supported expressivity class. TechVault is the comprehensive proving case. This work is tracked by GitHub issue series #317-#324; profile-upgrade follow-ons remain #311 and #312.

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `330` (SCN-010 inventory: webapp container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `361` (Add webapp ACES inventory)
- DOCUMENTS → GITHUB_ISSUE `317` (SCN-010: ACES TechVault cutover issue series and validation gates)
- DOCUMENTS → GITHUB_ISSUE `320` (SCN-010C: specify TechVault defensive stack and rendered configs in ACES SDL)
- DOCUMENTS → GITHUB_ISSUE `322` (SCN-010E: add static validation gate for ACES TechVault parity and conformance)
- DOCUMENTS → GITHUB_ISSUE `323` (SCN-010F: add live validation gate for ACES-driven TechVault deployment)
- IMPLEMENTS → GITHUB_ISSUE `318` (SCN-010A: inventory TechVault legacy surfaces for ACES parity)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/techvault_gate.py` (ACES TechVault static validation gate (public API + orchestrator))
- IMPLEMENTS → PULL_REQUEST `326` (Land SCN-010 parity inventory (#318))
- IMPLEMENTS → CODE_FILE `src/aptl/validation/_gate_checks.py` (ACES static validation gate check implementations)
- TESTS → TEST `tests/test_techvault_static_gate.py` (ACES static validation gate tests)
- IMPLEMENTS → PULL_REQUEST `359` (Add ACES inventory methodology tooling)
- DOCUMENTS → ADR `ADR-035` (Adopt ACES SDL as APTL's Scenario Authoring Surface)
- IMPLEMENTS → GITHUB_ISSUE `311` (Upgrade APTL backend conformance to orchestration-capable profile)
- IMPLEMENTS → GITHUB_ISSUE `312` (Upgrade APTL backend conformance to orchestration-evaluation profile)
- IMPLEMENTS → GITHUB_ISSUE `360` (SCN-010 inventory: shuffle-backend container (steady-state asset spec))
- IMPLEMENTS → CONFIG `.github/workflows/checks.yml` (aces-conformance advisory CI job + aces-sdl SHA pin recipe)
- IMPLEMENTS → PULL_REQUEST `316` (feat: scaffold ACES backend adapter (provisioning-only profile))
- IMPLEMENTS → CONFIG `containers/misp-suricata-sync/Dockerfile` (MISP Suricata sync image build dependencies for pinned ACES install)
- IMPLEMENTS → CONFIG `web/Dockerfile.api` (Web API image build dependencies for pinned ACES install)
- IMPLEMENTS → GITHUB_ISSUE `339` (SCN-010 inventory: kali container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `365` (Add kali container ACES inventory (#339))
- IMPLEMENTS → GITHUB_ISSUE `332` (SCN-010 inventory: ad container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `367` (feat: add ad aces inventory)
- IMPLEMENTS → CONFIG `uv.lock` (ACES SDL dependency lock for identity-authority schema consumption)
- TESTS → TEST `pre-commit run --all-files` (APTL repo policy validation for PR #377)
- TESTS → TEST `bin/install-aces-inventory-skill.sh --aces-repo /home/atomik/src/aces2 --claude-dir $tmpdir/claude --codex-dir $tmpdir/codex --codex-prompts-dir $tmpdir/prompts` (Installer isolated temp-directory symlink validation)
- IMPLEMENTS → PULL_REQUEST `381` (Add victim ACES inventory)
- IMPLEMENTS → PULL_REQUEST `382` (Add DNS ACES inventory)
- IMPLEMENTS → PULL_REQUEST `379` (Add fileshare ACES inventory)
- IMPLEMENTS → PULL_REQUEST `377` (Add ACES inventory skill installer)
- DOCUMENTS → DOCUMENTATION `AGENTS.md` (APTL agent guidance for installing ACES asset inventory capture skill)
- IMPLEMENTS → GITHUB_ISSUE `371` (Install ACES asset inventory capture skill from APTL)
- TESTS → TEST `bash -n bin/install-aces-inventory-skill.sh` (Installer shell syntax validation)
- TESTS → TEST `bin/install-aces-inventory-skill.sh --aces-repo /home/atomik/src/aces2 --dry-run` (Installer dry-run validation against ACES checkout)
- IMPLEMENTS → GITHUB_ISSUE `333` (SCN-010 inventory: fileshare container (steady-state asset spec))
- IMPLEMENTS → GITHUB_ISSUE `334` (SCN-010 inventory: workstation container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `378` ([codex] Add workstation ACES inventory)
- IMPLEMENTS → GITHUB_ISSUE `337` (SCN-010 inventory: victim container (steady-state asset spec))
- IMPLEMENTS → GITHUB_ISSUE `336` (SCN-010 inventory: dns container (steady-state asset spec))
- IMPLEMENTS → GITHUB_ISSUE `345` (SCN-010 inventory: suricata container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `383` (Add suricata ACES inventory (#345))
- IMPLEMENTS → GITHUB_ISSUE `340` (SCN-010 inventory: wazuh.manager container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `384` (Add Wazuh manager ACES inventory)
- IMPLEMENTS → PULL_REQUEST `385` (Add MISP ACES inventory)
- IMPLEMENTS → GITHUB_ISSUE `346` (SCN-010 inventory: misp container (steady-state asset spec))
- TESTS → TEST `uv run aptl aces-inventory validate docs/aces/inventory/wazuh.manager` (Wazuh manager ACES inventory validation gate)
- TESTS → TEST `uv run aptl aces-inventory gaps docs/aces/inventory/wazuh.manager` (Wazuh manager ACES inventory gap audit gate)
- IMPLEMENTS → GITHUB_ISSUE `347` (SCN-010 inventory: misp-db container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `390` (Implement MISP DB inventory)
- TESTS → TEST `uv run aptl aces-inventory validate docs/aces/inventory/misp-db` (MISP DB ACES inventory validation gate)
- TESTS → TEST `uv run aptl aces-inventory gaps docs/aces/inventory/misp-db` (MISP DB ACES inventory gap audit gate)
- IMPLEMENTS → GITHUB_ISSUE `342` (SCN-010 inventory: wazuh.dashboard container (steady-state asset spec))
- TESTS → TEST `uv run aptl aces-inventory validate docs/aces/inventory/wazuh.dashboard` (Wazuh dashboard ACES inventory validation gate)
- TESTS → TEST `uv run aptl aces-inventory gaps docs/aces/inventory/wazuh.dashboard` (Wazuh dashboard ACES inventory gap audit gate)
- IMPLEMENTS → PULL_REQUEST `394` (added: add wazuh dashboard ACES inventory)
- IMPLEMENTS → GITHUB_ISSUE `343` (SCN-010 inventory: wazuh-sidecar-db container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `396` (added: SCN-010 wazuh-sidecar-db ACES steady-state inventory (+ #388 secret-redaction reconciliation))
- IMPLEMENTS → GITHUB_ISSUE `357` (SCN-010 inventory: cortex container (steady-state asset spec))
- TESTS → TEST `tests/test_cortex_integration_config.py` (TheHive/Cortex integration configuration checks)
- TESTS → TEST `uv run aptl aces-inventory validate docs/aces/inventory/cortex` (Cortex ACES inventory validation gate)
- TESTS → TEST `uv run aptl aces-inventory gaps docs/aces/inventory/cortex` (Cortex ACES inventory gap audit gate)
- IMPLEMENTS → PULL_REQUEST `409` ([codex] Integrate and inventory Cortex)
- IMPLEMENTS → GITHUB_ISSUE `341` (SCN-010 inventory: wazuh.indexer container (steady-state asset spec))
- IMPLEMENTS → PULL_REQUEST `392` (added: SCN-010 wazuh.indexer ACES steady-state inventory)
- IMPLEMENTS → PULL_REQUEST `401` (Encode wazuh-indexer datastore surfaces unblocked by ACES #468/#469/#470)
- IMPLEMENTS → PULL_REQUEST `411` (Audit TechVault inventory captures)
- TESTS → TEST `uv run aptl aces-inventory validate docs/aces/inventory/wazuh.indexer` (Wazuh indexer ACES inventory validation gate)
- TESTS → TEST `uv run aptl aces-inventory gaps docs/aces/inventory/wazuh.indexer` (Wazuh indexer ACES inventory gap audit gate)
- IMPLEMENTS → GITHUB_ISSUE `321` (SCN-010D: route APTL public start path through ACES RuntimeManager handoff)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Public lab start orchestration route through ACES RuntimeManager handoff)
- TESTS → TEST `tests/test_lab.py` (Lab start ACES handoff routing regression test)
- IMPLEMENTS → PULL_REQUEST `501` (changed: route lab start through ACES runtime)
- IMPLEMENTS → PULL_REQUEST `506` (changed: generalize ACES provisioning realization)
- IMPLEMENTS → GITHUB_ISSUE `324` (SCN-010G: generalize ACES-to-APTL backend interpretation for equivalent scenario expressivity)
- DOCUMENTS → DOCUMENTATION `docs/sdl/runtime-architecture.md` (APTL ACES provisioning realization contract documentation)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/techvault_live_gate.py` (ACES live validation gate orchestrator (SCN-010F))
- IMPLEMENTS → CODE_FILE `src/aptl/validation/_live_gate_checks.py` (ACES live validation gate checks (SCN-010F))
- IMPLEMENTS → CODE_FILE `src/aptl/validation/_live_gate_probes.py` (ACES live validation gate probe helpers (SCN-010F))
- TESTS → TEST `tests/test_techvault_live_gate.py` (ACES live validation gate tests (SCN-010F))
- IMPLEMENTS → CODE_FILE `src/aptl/core/runtime/workflow_engine.py` (RTE-001 workflow execution engine)
- TESTS → TEST `tests/test_workflow_engine.py` (RTE-001 workflow engine tests)
- IMPLEMENTS → GITHUB_ISSUE `514` (APTL ACES orchestrator: report real RTE-001 workflow execution state)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/_account_parity.py` (ACES static-gate account provisioner-parity check (extracted from _gate_checks))
- IMPLEMENTS → GITHUB_ISSUE `#580` (Backend manifest truth-up + conformance re-verification)
- IMPLEMENTS → PULL_REQUEST `792` (fix(aces): truth up backend manifest)
- IMPLEMENTS → DOCUMENTATION `docs/architecture/issue-589-scenario-pack-capture-ownership-preflight.md` (RAES environment-pack ownership decision)
- TESTS → TEST `tests/test_scenario_pack_ownership_contract.py` (Scenario-pack ownership contract test)
- IMPLEMENTS → GITHUB_ISSUE `589` (Review APTL ownership for scenario-pack capture workflows)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_manifest.py`
- TESTS → TEST `tests/test_raes_backend.py`
- IMPLEMENTS → CODE_FILE `bin/install-raes-inventory-skill.sh`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization_model.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_orchestrator.py`
- TESTS → TEST `tests/test_raes_orchestrator.py`
- TESTS → TEST `tests/test_raes_evaluator.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_placement_realization.py`
- DOCUMENTS → DOCUMENTATION `docs/raes/techvault-static-validation-gate.md`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization_values.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_evaluator.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/_raes_evaluator_engine.py`
- IMPLEMENTS → CODE_FILE `src/aptl/validation/_gate_raes_cli.py` (RAES CLI conformance invocations for the static gate (split from _gate_checks.py for S104))
