# Scenario Authoring Boundary

APTL no longer maintains a local scenario language or parser. ADR-035 moved
scenario authoring and runtime handoff to RAES SDL.

Current operator-facing startup selection uses:

- `scenarios/catalog.json` for curated scenario IDs
- `aptl.core.scenario_catalog.resolve_scenario_selection()` for catalog or
  explicit path resolution
- `raes.parse_sdl_file` for SDL validation
- `aptl.backends.raes.start_raes_scenario()` for runtime handoff through RAES

The historical APTL-local SDL reference pages in this section are retained only
for old ADR links and design archaeology. They are not current authoring
guidance, not runtime input documentation, and not an alternate schema
authority.

For current TechVault authoring and validation, use the RAES pages:

- [TechVault Static Validation Gate](../raes/techvault-static-validation-gate.md)
- [TechVault Live Validation Gate](../raes/techvault-live-validation-gate.md)
- [Curated RAES Startup Variants](techvault-curated-variants.md)
