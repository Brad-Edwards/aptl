# Backend Conformance

This directory contains the repo-owned conformance kit for APTL runtime
contracts.

- `fixtures/` contains golden valid and invalid payloads grouped by contract
  schema name.
- `profiles/` contains backend capability profile declarations.

The runner validates:

- closed-world contract shape
- exact schema-version behavior
- semantic legality for runtime snapshots that contain workflow/evaluation
  state and history

The fixture corpus is intentionally plain JSON so non-Python backends can use
the same artifacts.
