# aptl-techvault-verifier

Semantic verification for the TechVault scenario running on the APTL backend.

This is deliberately **not** part of the `aptl-labs` distribution. Knowing that
`aptl-kali` is the attacker, that the defensive stack is Wazuh plus Suricata, and
what evidence proves a detection traversed it, is knowledge about one scenario on
one backend. APTL core must serve any scenario, so it holds none of it.

Installing this package is what gives the live gate a semantic verdict for
TechVault. Without it the gate reports `blocked`, rather than `passed` or
`failed`, because no verdict was possible.

The package registers `techvault.aptl` in the
`aptl.scenario_verifiers` entry-point group. The host admits it only when every
declared dimension matches exactly: extension API, TechVault pack source,
version and digest, plus APTL target version, profile, provider, and transport.
Empty declarations are not wildcards. The report records the distribution name
and version from installed package metadata rather than trusting plugin-authored
provenance.

The same distribution registers the guided profile's operation plan as
`guided-purple.techvault-attacker-target` in
`aptl.participant_mcp_smoke_plans`. Production qualification callers resolve
that exact installed plan from the admitted profile; they do not import this
package by name, and core ships no default smoke plan.

Core supplies bounded, deadline-clamped operations for network discovery,
container-scoped argv execution, and evidence collection. This package owns the
TechVault answer key: required nodes, target selection, nmap/failed-SSH activity,
and Wazuh correlation. Required nodes, the operations surface, and an admitted
shared-network target are prerequisites; if any is unavailable, no activity is
performed and the result is terminal `blocked`.

Where a plugin like this ultimately lives (beside the range, in its own
repository, alongside the scenario pack) is not settled. It sits in this repo for
now so the seam can be exercised end to end, but it builds and installs as its
own distribution, which is what makes "core ships zero adapters" a checkable
claim rather than an assertion.

CI independently builds the core and plugin wheels. It proves core-only
installation blocks, then installs this wheel and exercises entry-point
discovery with host-observed provenance. The same artifact check inspects both
the importable core package and its bundled `_labdata/src` payload for the known
TechVault answer keys.
