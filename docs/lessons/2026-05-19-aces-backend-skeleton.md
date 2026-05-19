---
date: 2026-05-19
side: both
sibling_entry:
follow_ups:
  - Brad-Edwards/aptl#310 — Phase A.2 wires `AptlProvisioner.apply()` through `aptl.core.lab.orchestrate_lab_start` + `aptl.core.deployment.DeploymentBackend`
  - Brad-Edwards/aces — open an issue tracking the `provisioner-node-types` vocabulary review (no `container` term; APTL containerized labs model as `vm`)
adr_impact:
  - ADR-035 — Phase A.1 lands the scaffolding the ADR's "Integration Guardrails" section anticipates; no amendment needed yet
contract_impact:
  - backend-manifest-v2 — APTL's manifest factory exercises the
    `concept_bindings` + `realization_support` requirements end-to-end
    for the first time outside `aces_backend_stubs`
profile_impact:
  - provisioning-only
---

## Context

Phase A.1 of #310: stand up the minimum credible surface that proves
ACES's `provisioning-only` profile is reachable from APTL — a pinned
dependency, a backend adapter module, a manifest factory, a target
factory, an explicit `register()` helper, and an advisory CI job. No
lab orchestration is wired yet; that's Phase A.2.

## What we expected

The ACES reference backend (`aces_backend_stubs`) made the manifest
look like the central declaration with a few helper fields. Plug in
APTL's identity, declare `provisioning-only`, return an empty
diagnostic list from `validate()`, and the conformance suite should
go green.

## What we found

Three contract-surface frictions surfaced during the scaffolding:

1. **`BackendManifest` requires `realization_support` AND
   `concept_bindings`.** Both must be non-empty for the manifest to
   construct; the constructor raises `ValueError` if either is
   missing. The reference stub (`aces_backend_stubs/stubs.py`)
   declares the full vocabulary, but the *minimum* shape needed to
   pass `provisioning-only` conformance isn't documented anywhere we
   could find — we cribbed from the stub.
2. **The controlled-vocabulary `provisioner-node-types` permits only
   `{vm, switch}`.** APTL's containerized lab hosts (Wazuh manager,
   Kali, victim, workstation) model most naturally as `container`,
   which isn't in the vocabulary. We declared `vm` to satisfy the
   closed-world validator. The lab IS effectively VM-like from a
   scenario perspective, but this is the first case where a real
   backend has to map its node taxonomy onto ACES's intentionally
   narrow controlled vocabulary. Worth a vocabulary review.
3. **The `Provisioner` `Protocol` is not `@runtime_checkable`.**
   `isinstance(obj, Provisioner)` raises `TypeError` rather than
   doing structural shape-checking. Tests that want to verify a
   target's provisioner conforms have to duck-type against
   `validate` and `apply` directly. The reference stub uses concrete
   classes so this doesn't bite it; downstream backend authors will
   trip on the same wall the first time they try to assert
   conformance in tests.
4. **`aces_contracts` cannot find its controlled-vocabulary catalog
   under a non-editable install.** `_repo_root()` is defined as
   `Path(__file__).resolve().parents[4]` and the catalog at
   `contracts/concept-authority/controlled-vocabularies-v1.json` is
   expected to live there. This assumes the source-tree layout
   `<repo>/implementations/python/packages/aces_contracts/__init__.py`,
   which only matches when aces-sdl is installed editably. A wheel
   install lands the package under `site-packages/aces_contracts/`,
   and `parents[4]` points at the venv root or higher — the catalog
   file isn't found, every BackendManifest construction call dies
   with `FileNotFoundError`. APTL's CI first hit this when the
   `python-tests` job installed aces-sdl as a transitive resolution
   from `pip install -e ".[dev]"`. Workaround applied: APTL's CI
   installs aces-sdl with `pip install -e "git+..."` BEFORE its own
   install, and `aces-sdl` is declared as an OPTIONAL `[aces]` extra
   rather than a core dep so the smaller APTL containers
   (misp-suricata-sync, web-api, webapp) don't pay the cost. Real
   fix lives on the ACES side: package the contracts/ tree as data
   files (PEP 561-style `package_data`) so the resolution works
   regardless of install mode, or expose the catalog via an
   `importlib.resources` lookup that doesn't rely on the source-tree
   path walk.

## Decision

- **fix-in-aptl** for #1 and #3: APTL's manifest factory declares
  both `realization_support` and `concept_bindings` blocks shaped
  after the reference stub, and the test suite duck-types instead of
  using `isinstance`. These are downstream adaptations to upstream
  contract shapes; the right home is the backend.
- **cross-repo-coordination** for #2: APTL declares `vm` for now and
  files a follow-up on the ACES side proposing either adding
  `container` to the `provisioner-node-types` vocabulary or
  documenting the mapping guidance for backends that surface
  container-shaped node taxonomies. APTL doesn't need it changed
  before Phase A.2 lands; the `vm` declaration is honest if
  imprecise.
- **fix-in-aces** for #1's documentation gap (separately surfaced in
  the ACES-side entry once it lands): the
  `aces_backend_protocols.capabilities.BackendManifest` docstring
  should call out that `concept_bindings` and `realization_support`
  are required non-empty, and the smallest acceptable shape for a
  `provisioning-only` backend should appear next to the profile JSON
  in `contracts/profiles/backend/provisioning-only.json`.

## Why this side

The vocabulary question (#2) is a contract decision — ACES owns the
controlled vocabulary, so the proposal belongs there. The manifest
documentation gap (#1) is upstream's to fix; APTL's adapter just
documents the gotcha in code comments meanwhile. The duck-typing
adjustment (#3) is APTL's to live with until ACES decides whether to
mark the protocols `@runtime_checkable` (which would couple ACES's
protocol surface to its consumers in a way that may not be intended;
arguably the duck-type-in-tests pattern is fine).

## Follow-ups

- aptl#310 Phase A.2 — wire `AptlProvisioner.apply()` through
  `DeploymentBackend` + `aptl.core.lab.orchestrate_lab_start`, raising
  `LabResult`-shaped diagnostics translated from ACES `Diagnostic`
  entries per ADR-035 guardrails.
- aces — vocabulary review issue (`provisioner-node-types`): add
  `container` term, or publish mapping guidance for container-shaped
  taxonomies.
- aces — manifest-construction documentation issue: document
  `realization_support` / `concept_bindings` minimums next to the
  profile JSONs.
- aces — `@runtime_checkable` decision on `aces_backend_protocols.protocols`
  (Provisioner / Orchestrator / Evaluator / ParticipantRuntime).
- aces — package the `contracts/` tree as installable package data
  (or use `importlib.resources`) so wheel installs work. The
  `parents[4]` source-tree-relative path walk is a real bug for any
  downstream that doesn't install aces-sdl editably (#310 Phase A.1
  hit it in APTL's CI before the editable-install workaround).
