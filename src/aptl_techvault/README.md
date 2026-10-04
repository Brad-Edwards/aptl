# aptl_techvault

Everything unique to the TechVault scenario that the APTL backend needs, in one
package, behind the entry points APTL discovers it through.

| Entry-point group | Name | What it supplies |
| --- | --- | --- |
| `aptl.pack_backend_interactions` | `techvault.aptl` | which pack components belong to which operator start group |
| `aptl.scenario_runtime_parameters` | `techvault` | fresh runtime-owned bindings for the exact qualified pack release |
| `aptl.scenario_startup` | `techvault` | content-qualified startup and native log-producer realization |
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
nothing further to install. The materialization boundary is in the code, not
the packaging: generic materialization consumes the admitted RAES model
without branching on TechVault names, while runtime parameters, startup
behavior and verification are reached through installed entry-point metadata.
Native evidence is an older built-in adapter under
`aptl.core.evidence.adapters`, with registrations still declared in APTL core;
this is not yet complete package-level scenario isolation.

## Customer database

The pack declares the customer database's listener, database, tables and login
role, and places its exact schema and seed SQL. Startup realizes those facts
from the declaration and runs the SQL once, in one transaction, as the declared
role. A marker on the database records that initialization, so a later startup
of the same run leaves participant changes alone. Startup refuses to reseed a
database it did not initialize.

The pack does not declare how clients authenticate to that database
(OpenRAE/env-packs#411), so the adapter chooses a posture that keeps the
authored attack paths meaningful. The declared role requires a SCRAM-SHA-256
password that matches the credential the portal presents and the workstation's
leaked `.pgpass` carries. The rule applies only to the network the database
and portal share. Startup checks that this rule is the first applicable entry
in PostgreSQL's effective rules. It then authenticates through the portal's
own client settings. The provider declares this choice in `runtime_selections`.
Each run's reproducibility record reports it under
`backend_evidence.scenario_runtime_selections`, separately from authored state.

## Startup verification traffic

The adapter verifier no longer runs the old `nmap` and failed-SSH checks; their
alerts outlived verification. Startup is nevertheless **not a zero-event
baseline**. The released SDL requires native evidence of a participant-equivalent
SQL-injection request, an authenticated MISP API write/read, and endpoint
telemetry. Those checks create bounded activity and may leave records in the
range. Startup also emits bounded syslog, database, DNS, SMB and HTTP activity
to prove that every declared Wazuh source has a working producer and fresh
manager-attributed telemetry. None of these records should be mistaken for
participant activity.

The framework owns capture windows and deadlines. The adapter receives scoped
backend operations, performs bounded readiness polling, and keeps credential
values inside their owning services rather than returning them as evidence.

## Compatibility

Compatibility is an atomic qualification claim, not a set of independent
allow-lists. `qualified_targets` names exact scenario-and-backend pairs, each
whole:

| Dimension | This release |
| --- | --- |
| Extension API | `2` |
| Scenario | `techvault`, source `env-pack`, pack version `0.1.1`, content digest `sha256:df00ea2a26…` |
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
