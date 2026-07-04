# Scenario Authoring Boundary

APTL no longer maintains a local scenario language or parser. ADR-035 moved
scenario authoring and runtime handoff to ACES SDL.

Current operator-facing startup selection uses:

- `scenarios/catalog.json` for curated scenario IDs
- `aptl.core.scenario_catalog.resolve_scenario_selection()` for catalog or
  explicit path resolution
- `aces_sdl.parse_sdl_file` for SDL validation
- `aptl.backends.aces.start_aces_scenario()` for runtime handoff through ACES

The historical APTL-local SDL reference pages in this section are retained only
for old ADR links and design archaeology. They are not current authoring
guidance, not runtime input documentation, and not an alternate schema
authority.

For current TechVault authoring and validation, use the ACES pages:

- [TechVault SDL Authoring Preflight](../aces/techvault-sdl-authoring-preflight.md)
- [TechVault Static Validation Gate](../aces/techvault-static-validation-gate.md)
- [TechVault Live Validation Gate](../aces/techvault-live-validation-gate.md)
- [Curated ACES Startup Variants](techvault-curated-variants.md)
