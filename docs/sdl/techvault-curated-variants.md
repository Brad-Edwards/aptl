# TechVault Curated ACES Startup Variants

Issue #534 adds small ACES SDL startup variants for TechVault. Their purpose is
to prove that APTL realizes Compose profiles from declared ACES node content,
not from the full TechVault scenario name or a preset.

## Authorities

- ACES SDL parsing and semantic validation belong to the installed ACES parser
  and processor/runtime compiler. APTL must not re-model ACES SDL with local
  Pydantic classes.
- APTL realization belongs to `aptl.backends.aces_realization` and the Compose
  profile index in `aptl.backends.aces_profiles`.
- Dependency expansion belongs to `aptl.backends.aces_dependency_closure`.
- Startup aliases belong to the strict `scenarios/catalog.json` schema and
  `aptl.core.scenario_catalog`; catalog rows are aliases, not behavior.
- Public startup still defaults to `scenarios/techvault-operational.sdl.yaml`.

## Guardrails

- Keep variants small: attacker/target, enterprise web, defensive minimum, or
  observability/core slices are valid only when they parse, compile, and realize
  without APTL-specific diagnostics.
- Tests must assert selected Compose profiles for each variant through
  `interpret_provisioning_plan` / `select_backend_profiles`.
- Tests must prove content-driven behavior by changing declared node content or
  using differently named scenarios with equivalent content. Scenario ids,
  filenames, and catalog names must not drive profile selection.
- Reuse existing TechVault node names, service aliases, networks, and runtime
  profile hints. Do not add a second profile map, scenario preset table, parser,
  exception hierarchy, or validation schema.
- New docs for each variant should state what it includes, omits, and proves.

## Curated variants

The catalog registers four curated variants alongside the default operational
scenario. Each one is a small single-file ACES SDL document under `scenarios/`.
The selected profile set is derived from declared node content and dependency
closure, then gated by the enabled container profiles in configuration. The
`otel` profile is always part of the public start set, so every variant includes
the OTEL core observability nodes.

| Catalog id | Includes | Omits | Selected profiles | Proves |
|---|---|---|---|---|
| `techvault-attacker-target` | Kali host and capture sidecar, one monitored victim, Wazuh manager and indexer, OTEL core | Enterprise web tier, the wider SOC stack | `kali`, `victim`, `wazuh`, `otel` | A red-team host against a monitored target; the victim pulls Wazuh through declared dependency content, not through the scenario name |
| `techvault-enterprise-web` | The enterprise tier (vulnerable webapp, database, AD, workstation), the Wazuh monitoring core, OTEL core | The wider SOC stack (Suricata, MISP, TheHive, Cortex, Shuffle), the red-team apparatus | `enterprise`, `wazuh`, `otel` | The enterprise tier realizes with the Wazuh core it requires and no SOC surface |
| `techvault-defensive-min` | Wazuh manager, indexer, dashboard, OTEL core | The wider SOC stack, attacker and enterprise components | `wazuh`, `otel` | Wazuh monitoring realizes without pulling the full `soc` profile |
| `techvault-observability-core` | OTEL collector, Tempo, Grafana | Every attacker, target, enterprise, and defensive component | `otel` | The smallest bounded startup surface APTL realizes from SDL |

Start a variant by catalog id:

```bash
aptl lab scenarios
aptl lab start --scenario techvault-attacker-target
```

The static realization proof for these variants lives in
`tests/test_techvault_curated_variants.py`. It parses, compiles, and realizes
each variant through `interpret_provisioning_plan` with no error-severity
`aptl.provisioner.*` diagnostics, asserts the selected Compose profile set for a
configuration that enables exactly the variant profiles, and proves the result is
content-driven through anti-collapse and rename checks.

Because `aptl lab start` boots with `docker compose --profile <selected>`, which
activates every service in a selected profile rather than only the declared ACES
nodes, the provisioner validates that the selected profile set is a valid Compose
project before starting the backend. When an activated service has a `depends_on`
target that the selection excludes, the provisioner refuses with an
`aptl.provisioner.compose-project-invalid` diagnostic instead of failing later
with a raw Compose error. This is why `techvault-enterprise-web` includes the
`wazuh` profile: the enterprise `workstation` host depends on `wazuh-manager`, so
the enterprise tier cannot boot without the Wazuh core.

## Security And Runtime Boundaries

- Catalog and explicit paths must remain project-contained and parser-validated.
- Static proof must use `_NoStartBackend` or equivalent no-start wiring; it must
  not start Docker while asserting parse/compile/realization behavior.
- Diagnostics and failures must use the existing ACES diagnostic path and APTL
  redaction helpers. Do not print raw SDL dumps, backend stderr, secrets, or
  rendered config.
- Variants must not introduce new config or environment keys. Durable
  non-secret knobs belong in `AptlConfig`; secret-bearing runtime artifacts stay
  under the existing ADR-028 / ADR-029 boundaries.
- Host port exposure, networks, volumes, and service dependencies remain
  Compose-owned. A variant can select profiles; it must not redefine Compose.

## Non-Goals

- No dependency closure beyond the curated slices needed here; broad subset
  closure belongs to #532.
- No arbitrary app or package installation from ACES feature descriptors.
- No replacement of the detailed `scenarios/techvault.sdl.yaml` inventory SDL.
- No change to the default operational startup scenario.
