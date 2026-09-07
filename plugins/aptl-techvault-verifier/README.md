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
`aptl.scenario_verifiers` entry-point group. The host admits it only when the
running range equals one declared `QualifiedTarget` exactly. Empty declarations
are not wildcards. The report records the distribution name and version from
installed package metadata rather than trusting plugin-authored provenance.

## Installing it

Install it explicitly beside APTL, before running the live gate:

```bash
pip install -e ./plugins/aptl-techvault-verifier --no-deps
```

Installation grants normal Python code-execution authority; entry points are a
discovery mechanism, not a sandbox.

## Compatibility and release policy

Compatibility is an atomic qualification claim, not a set of independent
allow-lists. `qualified_targets` names the exact scenario-and-backend
combinations this release was qualified against, each pair whole:

| Dimension | This release |
| --- | --- |
| Extension API | `2` |
| Scenario | `techvault`, source `env-pack`, pack version `0.1.0`, content digest `sha256:c532775575…` |
| Backend | RAES target `aptl` `0.1.0`, profile `full-remote-control-plane` |
| Transport | `docker-compose` and `ssh-compose` |

What that means in practice:

- **A pack release requires a verifier release.** Changed pack content is
  content this verifier was never qualified against, even when the pack version
  is unchanged. A changed version is likewise unqualified even when the digest
  happens to match. Either way the gate reports terminal `blocked` until a
  verifier release declares the new pair, and the version and digest move
  together because they are one claim.
- **Nothing is admitted by omission.** An empty declaration qualifies nothing,
  and no combination is inferred from a package version range. Every unqualified
  combination, malformed claim, and absent plugin is `blocked`, never passed,
  skipped, or reported as a detection failure.
- **Several pairs are allowed, each on its own evidence.** The two transports
  above are the same qualified pack content on the same target and profile;
  ADR-013 makes `docker-compose` versus `ssh-compose` the location of the Docker
  daemon rather than a difference in what the range realizes.
- **Python support is the intersection with core.** `requires-python` is
  `>=3.11`, matching `aptl-labs`, so there is no host APTL supports on which
  TechVault verification silently disappears.
- **The core dependency is a separate concern.** `dependencies` names the
  released `aptl-labs` range that supplies the imported extension contract.
  Runtime discovery still enforces the exact extension API version, which is
  what actually protects the contract; the range only keeps installation
  resolvable.

The distribution's version moves with either kind of change: a new qualified
pair or a change to the answer key. CI builds its wheel and sdist from this
directory with the repository's locked toolchain and asserts those artifacts
never appear in the directory core's release job uploads by glob, so it is never
folded into an `aptl-labs` release. Publishing it to an index is a further step
that needs its own package registration and trusted-publisher configuration; it
has not been published yet, and until it is, "install it beside APTL" means from
this checkout or a built artifact.

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
