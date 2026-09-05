# ADR-054: APTL-to-LilRAE Identity Continuity and Capability Ownership

## Status

proposed

## Date

2026-09-05

## Context

[Review #962](https://github.com/Brad-Edwards/aptl/issues/962) assesses the
APTL baseline before the product adopts the LilRAE name. APTL and LilRAE are
one product across a rename, not a source and destination product. TechVault is
a scenario pack selected by that product; its topology and integrations do not
create another product or user-experience layer. Complete means operationally
complete within the declared envelope; it does not mean every imaginable
environment.

The current distribution combines generic realization with TechVault startup,
eight scenario-selected MCP integrations, research apparatus, a local operator
UI, and appliance delivery. Renaming that distribution alone preserves the
coupling.

TechVault's pack content has already moved to
[OpenRAE/env-packs/packs/techvault](https://github.com/OpenRAE/env-packs/tree/main/packs/techvault)
for now. This ADR takes that location as current state and proposes no further
physical move or permanent repository choice. APTL and LilRAE name the same
backend project across migration; they are not two runtime layers around the
pack. Remaining work removes residual coupling and qualifies pack consumption.

## Proposed decision

Keep one backend execution path. LilRAE owns local admission, host diagnostics,
realization, readiness, native observation, evidence capture, recovery, reset,
and teardown. RAES remains the authority for portable meaning, processing,
runtime/control contracts, diagnostics, and conformance. Catalogs and env-packs
own scenario content and pack acquisition contracts.

Here, LilRAE names the same product after the rename. It does not name a new
host for APTL code or a parallel runtime.

The backend may implement sophisticated mechanisms when an adopted scenario
requires them. Complexity must have a named consumer and observable acceptance
test. Neither a minimal quickstart nor a fixed list of generic services defines
the maximum product capability.

| Surface | Owner and migration rule |
| --- | --- |
| Local lifecycle and Docker realization | LilRAE; preserve implementation lineage and behavior |
| RAES adapters and native readback | LilRAE; published public dependencies only |
| Safe run storage, sealing and export | Generic mechanisms in LilRAE; research policy in an extension |
| TechVault topology, vulnerable apps, service configuration and assets | Existing TechVault pack in OpenRAE/env-packs for now; consume acquired content with verified identity |
| Scenario verification and answer keys | Selected pack validation and executable verifier plugins, with explicit compatibility |
| Wazuh, SOC, red and reverse MCP integrations | Explicitly selected TechVault pack integrations; no automatic installation in the small profile |
| Plugin discovery and compatibility | One small installed-extension boundary; extensions are trusted executable code |
| Agent provider adapters and study/campaign features | Optional participant/research extensions over released contracts |
| Operator web UI | Optional LilRAE surface; scenario pages project acquired pack data |
| Sealed seat and workshop launcher | Optional delivery profile; consumes the same backend |
| Cloud federation, tenants, organizational scheduling and billing | Outside the personal-backend adoption gate |

Evolve the technical boundaries in behavior-preserving slices under
[LilRAE #3](https://github.com/OpenRAE/lilrae/issues/3). Record the source commit
and useful authorship/history. Do not maintain two active backend copies.
An old path can be retired only after a released replacement, parity evidence,
and migration guidance exist. Historical ADRs and evidence remain historical.

The tiny pack and TechVault use the same acquisition, admission, realization,
observation, reset, and teardown path. A convenience profile cannot bypass
admission because its pack ships nearby. Installed plugins require operator
trust; entry-point metadata is provenance, not code isolation.

## Existing ADR disposition

On acceptance, this decision clarifies ADR-001, ADR-003, ADR-007, ADR-013,
ADR-023, ADR-035, ADR-037, ADR-047 and ADR-053. It scopes ADR-002, ADR-006,
ADR-008 and ADR-019 through ADR-024 to the scenario packs or research profiles
that require them.
It supersedes the remaining APTL-owned portable-language authority implied by
ADR-014 through ADR-018. Backend execution of published contracts remains
valid; a second semantic authority does not.

These are proposed dispositions. Accepted records are not rewritten by this
review, and acceptance of this ADR does not certify implementation completion.

## Consequences and verification

- A tiny installed profile must work without TechVault pack bytes, SOC clients,
  scenario MCPs, research policy or provider credentials.
- The TechVault scenario pack must still work through independently installed
  packs and plugins. Shrinking the shared lifecycle cannot silently remove
  adopted behavior.
- Import-boundary and installed-wheel checks accompany migration parity tests.
- The current private `raes._source` type import and older-package fallback in
  the manifest must be removed or replaced through published upstream APIs.
- [#934](https://github.com/Brad-Edwards/aptl/issues/934) owns rename identity
  inventory; [#970](https://github.com/Brad-Edwards/aptl/issues/970) owns the
  lifecycle decomposition. This ADR does not create a release identity.

The filename is retained as a legacy locator for incoming links. Its former
“core and experience” wording is not an accepted architecture boundary.
