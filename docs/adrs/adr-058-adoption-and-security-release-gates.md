# ADR-058: Adoption and Security Release Gates

## Status

proposed

## Date

2026-09-05

## Context

APTL has substantial tests, pinned dependencies, CI scans and release tooling.
The reviewed pre-commit and static gates pass. Yet the full range still has open
functional and isolation defects. ADR-026's advisory scanning rule also groups
intentional vulnerable targets with the components that protect the operator.

The inspected dev protection contexts do not require dependency audit or the
RAES scenario gate. A workflow job that fails is not necessarily a merge gate.
The current README's full TechVault default and small-scenario promises also
need qualification against released pack behavior.

## Proposed decision

Separate security treatment by authority boundary. Core CLI/API, process and
MCP brokers, evidence stores, and build/release infrastructure receive normal
security gates. An intentional target weakness needs a bounded exception tied
to pack/component/version, purpose, owner, expiry and containment evidence.
There is no blanket cyber-range exemption for host/control-plane defects.

Use a small required PR gate for impacted code, schemas, security regressions,
dependency policy and installed-artifact checks. Use isolated-daemon and clean
host jobs for release-level realization, failure/recovery and journey evidence.
Expensive advanced-profile tests need not run on every prose edit, but a release
cannot claim that profile without matching evidence.

The release report names exact CLI, RAES, env-packs, pack/plugin, image and
runtime versions; OS/architecture; resource and timing assumptions; conformance
results; scenario readback; limitations; reset/teardown results; and residual
state. Keep native diagnostics private while exporting bounded operator help.

The Hub journey has one discoverable entry point and uses normal released
acquisition. It must demonstrate useful readiness, one meaningful action,
inspectable evidence, one bounded change with a corresponding result, and
verified reset/teardown. The [Hub #12 protocol](https://github.com/OpenRAE/hub/issues/12)
requires inspectable first-result evidence within ten minutes, including
acquisition. Record cold acquisition and warm execution separately; change,
reset and teardown then have their own declared deadlines. Container start
time and cached developer-machine runs do not satisfy the acquisition gate.

Full TechVault is qualified separately as the advanced APTL experience. Its
service and telemetry parity requirements remain. An optional web UI or model
provider cannot become an implicit tiny-profile prerequisite.

## Existing ADR disposition

On acceptance, supersede ADR-026's blanket advisory treatment for platform
security findings, while retaining its appropriate treatment of intentional
target weaknesses and advisory aggregate posture scores. Clarify ADR-010,
ADR-030, ADR-038, ADR-044 and ADR-050. Preserve immutable historical records.

## Consequences and implementation

- [#969](https://github.com/Brad-Edwards/aptl/issues/969) implements the gate
  matrix and verifies actual repository settings through the normal governance
  route. This review changes no branch protection or release settings.
- Local and CI test selection must agree. The current `integration` marker
  includes filesystem/subprocess tests; those are not all live-lab tests.
- Common MCP changes rebuild all consumers. Use lock-based installs consistently
  and add real transport/boundary tests where source wrappers have no suite.
- Doc claims and support statements follow measured profiles. Badges and a
  successful mock-backed conformance run do not substitute for adoption proof.
- LilRAE #4/#9/#10 and APTL #870/#685 own the corresponding product evidence.
  Hub #3 owns the composed user journey. Paired research and broad capability
  expansion remain outside this gate.
