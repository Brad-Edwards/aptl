# aptl_techvault

Everything unique to the TechVault scenario that the APTL backend needs, in one
package, behind the entry points APTL discovers it through.

| Entry-point group | Name | What it supplies |
| --- | --- | --- |
| `aptl.pack_backend_interactions` | `techvault.aptl` | which pack components belong to which operator start group |
| `aptl.scenario_verifiers` | `techvault.aptl` | the semantic answer key: is the declared defensive stack realized, does the attacker reach its peers |
| `aptl.participant_mcp_smoke_plans` | `guided-purple.techvault-attacker-target` | the exact MCP operations that qualify a participant |

## Why it lives here

This is an adapter, not portable content. It names `aptl-kali`,
`aptl-wazuh-manager`, APTL component addresses and APTL operator groups, because
that is what an answer key for one scenario on one backend is made of. Hand it to
another backend and it means nothing.

That is also why it belongs to the backend rather than to the scenario author. An
author cannot write the adapter for a backend they have never seen, and many
backends are private, so they never could. A scenario declares the capability
profile it needs and a backend declares conformance to it; the adapter answers
the separate question of whether the scenario's expectations actually held.

It ships inside the `aptl-labs` distribution and releases with it, so `pipx
install aptl-labs` gives an operator every extension surface TechVault owns with
nothing further to install. The boundary that matters is in the code, not the
packaging: no module under `aptl.` holds scenario knowledge, every surface here
is reached only through installed entry-point metadata, and a second scenario
adds a package beside this one rather than editing the framework. Conformance
tests assert each of those.

## What it does not do

It generates no activity in the range. An earlier check drove `nmap` and failed
SSH authentication from the attacker node and then read Wazuh back, to prove an
event traversed the sensor and the SIEM. Those alerts and sensor records outlived
the run, because the live gate's destructive cleanup runs before its boot rather
than after, so a validated range was no longer in a clean pre-attack state. What
remains is observation: the declared nodes are realized and the attacker reaches
its shared-network peers.

It also owns no windows, deadlines, polling, credentials or backend access. Those
are framework concerns reached through the operations surface.

## Compatibility

Compatibility is an atomic qualification claim, not a set of independent
allow-lists. `qualified_targets` names exact scenario-and-backend pairs, each
whole:

| Dimension | This release |
| --- | --- |
| Extension API | `2` |
| Scenario | `techvault`, source `env-pack`, pack version `0.1.0`, content digest `sha256:c532775575…` |
| Backend | RAES target `aptl` `0.1.0`, profile `full-remote-control-plane` |
| Transport | `docker-compose` and `ssh-compose` |

A pack release requires an adapter release. Changed pack content is content this
adapter was never qualified against, even when the pack version is unchanged, and
a changed version is unqualified even when the digest happens to match. Version
and digest move together because they are one claim. Until an adapter release
declares the new pair, the gate reports terminal `blocked`.

Nothing is admitted by omission. An empty declaration qualifies nothing, no
combination is inferred from a package version range, and every unqualified
combination, malformed claim or absent adapter is `blocked` rather than passed,
skipped, or reported as a detection failure. The two transports above are the
same qualified pack content on the same target and profile; ADR-013 makes
`docker-compose` versus `ssh-compose` the location of the Docker daemon rather
than a difference in what the range realizes.

A gated test resolves the admitted pack identity through `env_pack_bundle()` and
fails when any declaration here diverges from it, so drift is caught in CI rather
than surfacing as an unexplained blocked gate.
