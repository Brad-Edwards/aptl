# TechVault static validation gate

The static validation gate (`aptl.validation.techvault_gate`) blocks an ACES
SCN-010 cutover unless the TechVault scenario is parseable, semantically valid,
conformance-aligned against the canonical ACES `backend-manifest-v2` surface,
realizable into a concrete provisioning plan, and account-consistent between
the SDL and the provisioner. It implements requirement SCN-010 (issue #322).

The gate is scenario-generic. `validate_scenario()` takes a scenario path, a
backend profile, the ACES corpus roots, and a target name, so the next scenario
in APTL's expressivity class passes through by changing inputs rather than by
editing the gate. TechVault is the proving input, never a hardcoded branch.

## What the gate checks

`validate_scenario()` composes existing authorities in order and returns a
`GateReport`. Each stage is one `GateCheck`:

1. **Parse.** The ACES reference parser (`aces_sdl.parse_sdl_file`) accepts
   `scenarios/techvault-operational.sdl.yaml`.
2. **Import lock** (when the scenario declares imports and `check_imports` is
   enabled). `aces sdl verify-imports` verifies the committed
   `aces.lock.json` next to the scenario against a fresh resolution. The
   lockfile's local `resolved_source` is checkout-independent (ACES #551), so
   this passes on CI and any developer checkout and fails only when an
   imported module changes without re-running `aces sdl resolve`.
3. **Compile.** `aces_processor.compiler.compile_scenario_runtime_model` runs
   semantic validation against the concept-authority corpus and produces the
   runtime model.
4. **Backend conformance.** APTL's canonical `backend-manifest-v2` target passes
   `run_target_conformance()` for the `full-remote-control-plane` profile, and
   the published `aces conformance backend --profile full-remote-control-plane`
   command runs against the bundled contract corpus. A missing corpus, profile
   artifact, or conformance command is a gate failure with an actionable
   diagnostic, never a downgraded warning and never a reason to accept an
   APTL-local manifest approximation.
5. **Provisioning realization.** The interpreter realizes the provisioning plan
   with no errors and produces nodes, services, and networks. It computes the
   dependency closure for selected nodes from ACES provisioning dependencies
   and Compose `depends_on` metadata before selecting backend profiles, so a
   subset scenario pulls in required support profiles or fails with ACES
   diagnostics for missing, ambiguous, or disabled support services. The
   selected Compose profiles must match the public lab-start profile set, so a
   scenario that would instantiate a partial range fails the gate. The
   realization is driven by declared content, not by the scenario identifier.
6. **Account provisioner parity.** Every account the SDL declares is a real,
   clean-start-realized fixture in the provisioner script, not a phantom
   declaration: group membership, mail attributes, SPNs, and the disabled flag
   must all agree between the SDL and what the provisioner actually creates
   (#689).

## Backend manifest

APTL publishes its capability declaration as the canonical ACES
`backend-manifest-v2` surface (`aces_backend_protocols.capabilities`) through
`create_aptl_manifest()`. The previous APTL-local manifest shim is removed: a
local dataclass approximation is not accepted as conformance evidence.

## Advisory today, blocking at cutover

The gate runs today as the advisory `aces-scenario-gate` CI job
(`continue-on-error: true`), which surfaces failures on the pull request
without blocking merge, while the fast gate-logic tests run in the blocking
default test suite. A future cutover PR removes `continue-on-error` to make
the full-scenario gate blocking.

## Running the gate

The fast gate-logic tests run in the default suite:

```
pytest tests/test_techvault_static_gate.py -m "not integration"
```

The full-scenario gate parses the full TechVault tree and spawns the `aces`
CLI, which takes minutes, so it is integration-marked. Run it before pushing a
scenario or manifest change:

```
pytest tests/test_techvault_static_gate.py -m integration
```

or through the manual pre-commit hook:

```
pre-commit run aces-scenario-gate --hook-stage manual
```

The gate needs only the installed `aces-sdl` wheel, which bundles the contract
corpus, and the `aces` command. It does not require a separate corpus checkout.
