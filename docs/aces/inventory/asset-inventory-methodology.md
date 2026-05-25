# ACES Asset Inventory Methodology Has Moved

APTL no longer owns or republishes the participant-discoverable asset
inventory capture methodology. The canonical methodology now lives in ACES:

- Methodology:
  <https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>
- Methodology assurance report:
  <https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/methodology-assurance-report.md>
- ACES asset inventory capture skill:
  <https://github.com/Brad-Edwards/aces/tree/dev/.codex-skills/aces-asset-inventory-capture>

APTL remains a downstream implementation and validation target. This repo owns
the TechVault evidence bundles, the `mapping-ledger.yaml` records captured for
those bundles, and the current reference ledger CLI:

```shell
aptl aces-inventory schema
aptl aces-inventory validate <asset-dir>
aptl aces-inventory gaps <asset-dir>
```

Use the ACES methodology before starting new capture work. Use APTL's CLI and
existing evidence bundles only as downstream implementation artifacts for
TechVault captures.
