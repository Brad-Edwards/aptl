# AD ACES Inventory Preflight

This note records the local architecture preflight for SCN-010 / issue #332.
The Ground Control `gc_codex_architecture_preflight` call completed and wrote
the issue phase marker, but the tool did not create a repo-local note file.

## Binding Guardrails

- Keep this work as an ACES inventory and specification update. Evidence,
  Docker output, package manifests, scanner output, checksums, and ledgers are
  proof inputs only; catalogued facts that ACES can express belong in
  `scenarios/techvault.sdl.yaml`.
- Do not create an APTL-local schema, parser, validator, Pydantic model, or
  runtime exception hierarchy for AD inventory facts.
- Reuse the ACES-owned inventory methodology at
  <https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>,
  `src/aptl/core/aces_inventory.py`, `src/aptl/cli/aces_inventory.py`, the
  existing webapp and db inventory bundles, and `docs/aces/parity-inventory.yaml`.
- Redact AD administrator credentials, generated flags, Kerberos/Samba secret
  material, Wazuh client keys, and private key contents from committed evidence.
- Keep legacy `aptl.core.sdl` and `scenarios/*.yaml` functional until the
  ADR-035 cutover PR. This issue does not change backend runtime behavior or
  flip default scenario selection.

## Applied Scope

The implementation captures the realized `aptl-ad` container after a fresh
`uv run aptl lab stop -v -y && uv run aptl lab start --skip-seed`, then records
the AD inventory under `docs/aces/inventory/ad/`, maps every catalogued fact in
`mapping-ledger.yaml`, and encodes the AD host, Samba domain, runtime, network,
service, identity, vulnerability, content, and relationship facts in
`scenarios/techvault.sdl.yaml`.
