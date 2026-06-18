# TechVault live validation gate

The live validation gate (`aptl.validation.techvault_live_gate`) is the
operational counterpart to the [static validation
gate](techvault-static-validation-gate.md). The static gate parses, compiles,
conformance-checks, and interprets the scenario without starting Docker. The
live gate boots the full TechVault lab through APTL's public start path and
proves the running range is realized from the interpreted ACES model rather than
from a TechVault preset, then captures operational and provenance evidence in
the run archive. It implements requirement SCN-010 (issue #323).

The gate is scenario-generic by construction. `validate_live_deployment()` takes
a scenario path, a backend profile, the project directory, and a run id, so the
next scenario in APTL's `provisioning-only` expressivity class passes through by
changing inputs rather than by editing the gate. TechVault is the proving input,
never a hardcoded branch (ADR-035).

APTL's public start path (`orchestrate_lab_start()`), however, is currently
hardwired to the default scenario (`scenarios/techvault.sdl.yaml`) and the
`provisioning-only` capability profile; it does not yet accept a caller-supplied
scenario or profile. So the gate verifies up front that the scenario and profile
it was asked to validate are the ones the public start path will actually boot,
and fails loud before any destructive boot if they diverge — it never validates
one model while booting another. When the public start path learns to honor a
caller-supplied scenario/profile, this guard relaxes to thread them through
instead of rejecting them.

## What the gate checks

`validate_live_deployment()` composes existing lifecycle, snapshot, and
collector owners and returns a `LiveGateReport`. Each stage is one
`LiveGateCheck` tagged with a stable failure category so a failure names the
layer that broke:

1. **Static prerequisite** (`aces_specification`). The static gate runs first. A
   parse, compile, conformance, or parity failure blocks the live boot rather
   than degrading to a warning.
2. **Boot-input agreement** (`backend_instantiation`). The scenario and profile
   under validation must be the ones the public start path will actually boot
   (the default scenario and the `provisioning-only` profile). A mismatch is a
   hard failure raised before any destructive boot, so the gate never validates
   one model while booting another.
3. **ACES-driven boot** (`backend_interpretation` or `backend_instantiation`).
   The gate computes the realization matrix from `RuntimeManager.plan()` and
   `interpret_provisioning_plan()`, the same interpretation `AptlProvisioner`
   performs, so the expected node, service, network, and profile surface is
   keyed by ACES resource addresses. It then runs `stop_lab(remove_volumes)`
   cleanup and `orchestrate_lab_start()`, whose only container-start path is the
   ACES handoff in `_step_start_containers()`. A realization with errors fails as
   `backend_interpretation`; a failed boot fails as `backend_instantiation`.
4. **Defensive-stack readiness** (`defensive_stack_readiness`). Every
   ACES-realized node maps to a running, healthy container in the post-boot
   snapshot. Pass or fail is keyed to the realized node surface, not a hardcoded
   container list. Unhealthy non-node infrastructure is a degraded note rather
   than a hard failure of the scenario surface.
5. **Kali reachability** (`kali_reachability`). From Kali, the gate reaches every
   lab host it shares a declared network with. Targets come from network
   co-membership in the snapshot (the realized network attachments), not a
   hardcoded host list. Every probe runs through
   `DeploymentBackend.container_exec()`.
6. **Telemetry evidence path** (`evidence_capture`). The gate generates one
   representative event from Kali against a reachable host, then collects
   Suricata EVE and Wazuh alerts in a bounded window through the existing
   collectors. At least one evidence artifact must traverse the defensive stack.
7. **Scenario variation** (`backend_interpretation`). Two declared ACES nodes
   from the booted scenario run through the same interpreter path and must yield
   distinct realization details. This is the anti-collapse property of #324
   (SCN-010G) generalized as a live diagnostic.
8. **Run-archive manifest** (`evidence_capture`). Written last so the persisted
   archive reflects the complete check set, the gate writes scenario identity,
   ACES provenance (realization details with resource addresses preserved), the
   selected profiles, validation evidence, the post-boot snapshot, and the
   telemetry summary through `LocalRunStore`'s redacting boundary (ADR-029).

## Failure categories

A failing report names the layers that broke, drawn from this closed set:
`aces_specification`, `backend_interpretation`, `backend_instantiation`,
`defensive_stack_readiness`, `kali_reachability`, and `evidence_capture`. The
categories map onto existing ACES diagnostics and APTL startup diagnostics. The
gate adds no parallel exception hierarchy.

## Run-archive manifest

The manifest lands at `<run-store>/<run-id>/live-gate/manifest.json` under the
schema `aptl.live-gate.manifest/v1`. It records:

- **`scenario`**: the scenario identity (path and name).
- **`aces_provenance`**: the realization details verbatim (node addresses,
  aliases, profiles, services, rendered configs, evidence and telemetry paths,
  networks, static addresses, and placements), the ACES-selected compose
  profiles, and the interpretation diagnostic count. This is the auditable proof
  that the lab was realized by interpreting ACES content rather than by a preset.
- **`validation`**: each check's name, category, outcome, and diagnostics.
- **`snapshot`**: the post-boot range snapshot (containers, networks, health,
  endpoints).
- **`evidence`**: the telemetry-path summary (event types and counts, never raw
  payloads).
- **`evaluator_surfaces_deferred`**: objectives, scoring, and the evaluator
  run-archive output, each tracked by issue #312.

## Observable parity

The live gate is validation tooling and a run-archive writer rather than new
scenario content. The TechVault steady-state observables are already encoded in
`scenarios/techvault.sdl.yaml` by the inventory passes and proven by the static
gate. The evaluator surfaces (objectives, scoring, injects, workflows, and the
evaluator run-archive output) are deferred to issue #312, which promotes APTL
beyond the `provisioning-only` profile. The gate therefore adds no
ACES-expressible observable surface, leaves `required_surface_coverage`
unchanged, and files no ACES expressivity blocker. The run archive is proof of
what the model realized; it does not substitute for SDL encoding.

## Prerequisites

The gate boots the full lab, so the runner needs:

- Docker with enough memory and disk for the full TechVault stack (the SOC tools
  alone need several gigabytes).
- A populated `.env` with real secrets. The boot refuses to start while
  sensitive values are still `.env.example` placeholders.
- The installed `aces-sdl` wheel and the `aces` command for the static
  prerequisite.
- An isolated, project-scoped Docker daemon. The destructive cleanup removes the
  `aptl` compose project's volumes, so do not run it against a shared daemon.

## Running the gate

The gate is destructive and minutes long. It targets maintainers and a
documented CI runner rather than fast CI or pre-commit. The fast gate-logic
tests that cover the orchestrator and every check branch run in the default
suite without a lab:

```
pytest tests/test_techvault_live_gate.py -m "not integration"
```

Run the full destructive boot through the CLI:

```
aptl lab validate-live
```

The command warns and prompts before destroying lab data. Pass `--yes` to skip
the prompt in automation, or `--skip-clean-boot` to validate an already-running
lab without the destructive `stop -v` and reboot. The `--scenario` and
`--profile` options exist for the scenario-generic seam, but until the public
start path accepts a caller-supplied scenario/profile they must match what that
path boots (the default scenario and `provisioning-only`); the gate fails the
boot-input agreement check otherwise. `--run-id` sets the run-archive id.

The same boot runs as the explicitly gated integration test:

```
APTL_LIVE_GATE=1 pytest tests/test_techvault_live_gate.py -m integration
```

Without `APTL_LIVE_GATE=1` the destructive test stays skipped, so an ordinary
`pytest -m integration` run never tears down a lab.
