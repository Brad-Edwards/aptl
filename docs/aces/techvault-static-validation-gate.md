# TechVault static validation gate

The static validation gate (`aptl.validation.techvault_gate`) blocks an ACES
SCN-010 cutover unless the TechVault scenario is parseable, semantically valid,
conformance-aligned against the canonical ACES `backend-manifest-v2` surface,
and proven to encode every required observable surface (or to defer it with a
linked tracking issue). It implements requirement SCN-010 (issue #322) and
records its decisions against the parity inventory.

The gate is scenario-generic. `validate_scenario()` takes a scenario path, a
backend profile, the ACES corpus roots, and a target name, so the next scenario
in APTL's expressivity class passes through by changing inputs rather than by
editing the gate. TechVault is the proving input, never a hardcoded branch.

## What the gate checks

`validate_scenario()` composes existing authorities in order and returns a
`GateReport`. Each stage is one `GateCheck`:

1. **Parse.** The ACES reference parser (`aces_sdl.parse_sdl_file`) accepts
   `scenarios/techvault.sdl.yaml`.
2. **Import lock.** `aces sdl verify-imports` verifies the committed
   `scenarios/aces.lock.json` against a fresh resolution. The lockfile's local
   `resolved_source` is checkout-independent (ACES #551), so this passes on CI
   and any developer checkout and fails only when an imported module changes
   without re-running `aces sdl resolve`.
3. **Compile.** `aces_processor.compiler.compile_scenario_runtime_model` runs
   semantic validation against the concept-authority corpus and produces the
   runtime model.
4. **Backend conformance.** APTL's canonical `backend-manifest-v2` target passes
   `run_target_conformance()` for the `orchestration-capable` profile, and the
   published `aces conformance backend --profile orchestration-capable` command
   runs against the bundled contract corpus. A missing corpus, profile artifact,
   or conformance command is a gate failure with an actionable diagnostic, never
   a downgraded warning and never a reason to accept an APTL-local manifest
   approximation.
5. **Provisioning realization.** The interpreter realizes the provisioning plan
   with no errors and produces nodes, services, and networks. It computes the
   dependency closure for selected nodes from ACES provisioning dependencies
   and Compose `depends_on` metadata before selecting backend profiles, so a
   subset scenario pulls in required support profiles or fails with ACES
   diagnostics for missing, ambiguous, or disabled support services. The
   selected Compose profiles must match the public lab-start profile set, so a
   scenario that would instantiate a partial range fails the gate. The
   realization is driven by declared content, not by the scenario identifier.
6. **Parity manifest.** Every required observable surface in
   `docs/aces/parity-inventory.yaml` under `required_surface_coverage` is either
   represented (proven by real compiled evidence) or deferred with a linked
   tracking issue.

## Backend manifest

APTL publishes its capability declaration as the canonical ACES
`backend-manifest-v2` surface (`aces_backend_protocols.capabilities`) through
`create_aptl_manifest()`. The previous APTL-local manifest shim is removed: a
local dataclass approximation is not accepted as conformance evidence.

## Required surface coverage

The parity inventory records, for each required surface, whether TechVault
represents it today or defers it to a follow-up. Startup surfaces (nodes,
services, vulnerabilities, features, Kali apparatus, defensive-stack configs,
and health) are represented. Remaining evaluator and scenario-flow surfaces
(injects, workflows, objectives, scoring, and evaluator run-archive evidence)
are deferred to issue #312. A surface that is neither represented with evidence
nor deferred with an issue fails the gate.

## Advisory in Phase A, blocking at cutover

ACES adoption runs in two phases (ADR-035). The gate behaves the same in both
phases but its enforcement strength differs:

- **Phase A.** Fast gate-logic tests run in the blocking default test suite. The
  full-scenario gate runs as the advisory `aces-scenario-gate` CI job, which
  surfaces failures on the pull request without blocking merge. Deferred
  surfaces are allowed when they carry a tracking issue.
- **Phase B (cutover).** The cutover pull request removes `continue-on-error`
  from the CI job to make the full-scenario gate blocking, and runs the gate
  with `phase="phase_b"`, which disallows deferrals and requires full
  representation.

## Running the gate

The fast gate-logic tests run in the default suite:

```
pytest tests/test_techvault_static_gate.py -m "not integration"
```

The full-scenario gate parses the complete TechVault tree and runs
`aces sdl verify-imports`, each of which takes minutes, so it is
integration-marked. Run it before pushing a scenario, manifest, or parity
change:

```
pytest tests/test_techvault_static_gate.py -m integration
```

or through the manual pre-commit hook:

```
pre-commit run aces-scenario-gate --hook-stage manual
```

The gate needs only the installed `aces-sdl` wheel, which bundles the contract
corpus, and the `aces` command. It does not require a separate corpus checkout.
