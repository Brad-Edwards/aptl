APTL publishes versioned JSON Schema documents here for language-neutral
external contracts. These schemas are generated from the repo-owned contract
models in `src/aptl/core/runtime/contracts.py` via:

`uv run python scripts/generate_contract_schemas.py`

They are the machine-readable source of truth for:
- SDL authoring input
- instantiated scenarios
- backend manifests
- runtime snapshots
- workflow result envelopes
- workflow history streams
- operation receipts and statuses
