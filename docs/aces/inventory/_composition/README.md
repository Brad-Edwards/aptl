# TechVault Scenario Composition Inventory

This bundle captures the SCN-010 TechVault scenario composition connective tissue for issue #329. It is a runtime-composed scenario inventory, not a per-image or per-container asset bundle. The per-asset steady-state evidence remains under the sibling `docs/aces/inventory/<asset>/` directories; this bundle indexes and maps the cross-asset facts that make those assets operate as one scenario.

Scope covered here:

- network topology and static placement across `redteam-net`, `dmz-net`, `internal-net`, and `security-net`
- authored service dependencies and selected Compose readiness dependencies
- shared volume and bind-mount handoff surfaces
- DNS, trust, account-to-host, and content placement summaries
- observation chains into Wazuh and Suricata
- defensive workflow chains across Shuffle, TheHive, Cortex, MISP, and Suricata
- authored-versus-realized separation for the composition view
- red/blue participant framing through `entities` and `agents` in `scenarios/techvault.sdl.yaml`

The inventory is stored in `docs/aces/inventory/_composition/` and the generated evidence is under `docs/aces/inventory/_composition/evidence/`.

## Capture

Run from the repository root:

```bash
docs/aces/inventory/_composition/capture-evidence.sh
uv run aptl aces-inventory validate docs/aces/inventory/_composition
uv run aptl aces-inventory gaps docs/aces/inventory/_composition
```

The capture script is non-destructive. It reads committed SDL, Compose, and existing per-asset inventory bundles. It intentionally does not run `aptl lab stop -v && aptl lab start`, container scanners, osquery, or post-attack workflow probes because the target is the TechVault scenario composition rather than a single runtime image or root filesystem. Per-asset bundles own image/package/filesystem scanner baselines.

No raw secret values are copied into composition evidence. Secret-bearing configuration is represented as SDL/Compose field ownership and sanitized relationship/account placement only.

No known ACES expressivity gap remains for the catalogued TechVault scenario composition facts. Remaining limits are capture-scope limits: this bundle is a static composition snapshot and does not prove a fresh clean-lab rebuild or workflow execution trace.
