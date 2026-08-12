# Scenario Authoring Boundary

APTL no longer maintains a local scenario language or parser. ADR-035 moved
scenario authoring and runtime handoff to RAES SDL.

## Companion repositories

Scenario authoring and the reusable environment-pack format are defined in the
RAES companion repositories, not in APTL:

- [OpenRAE/rae](https://github.com/OpenRAE/rae): the RAES SDL, tools, runtime,
  and reference backend. It owns SDL shape and semantics.
- [OpenRAE/env-packs](https://github.com/OpenRAE/env-packs): the RAES companion
  repository for environment-pack definitions, formats, templates, schemas,
  validation, tooling, and authoring/adoption guidance. Use it to author and
  validate environment packs.

These are authoring and reference links, not runtime source URLs or trust roots.
APTL consumes published RAES SDL and packs. How a scenario *runs* as a lab (the
Compose topology, container realization, lab lifecycle, credentials, and
captured evidence) stays APTL-owned and is documented in APTL's own pages.

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
