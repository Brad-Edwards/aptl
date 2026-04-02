# Formal Specs

Optional formal artifacts for APTL semantic and stateful subsystems live under:

`specs/formal/<domain>/`

Examples:

- `specs/formal/workflows/`
- `specs/formal/objectives/`
- `specs/formal/planner/`
- `specs/formal/runtime-contracts/`

Cross-domain semantic notes that constrain future phases may also live at the
top level when they apply across multiple domains, for example
`specs/formal/composition-readiness.md`.

Each domain directory should include a short README that explains:

- scope
- invariants or properties under study
- relationship to implementation and tests

This directory is intentionally optional. See
`docs/reference/coding-standards.md` and
`docs/adrs/adr-020-lightweight-formal-methods-policy.md` for the policy on
when formal artifacts are warranted.
