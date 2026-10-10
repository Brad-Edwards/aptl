# ADR-062: LilRAE Name and Naming Convention for New Code

## Status

accepted

## Date

2026-10-05

## Context

The APTL (Advanced Purple Team Lab) repository was transferred into the OpenRAE
organization and renamed to
[OpenRAE/lilrae](https://github.com/OpenRAE/lilrae). The transfer retained the
source, Git history, features, and issue tracker.
[Issue #1229](https://github.com/OpenRAE/lilrae/issues/1229) records the
tracker reconciliation, and
[issue #1230](https://github.com/OpenRAE/lilrae/issues/1230) updates repository
location wiring.

Public-facing documentation still introduced the project as APTL. Users who
arrive through the renamed repository need to recognize LilRAE as the same
project. The code, packaging, configuration, and runtime still carry `aptl`
identifiers that existing installations, scripts, and records depend on.

[ADR-054](adr-054-lilrae-core-and-experience-ownership.md) describes APTL and
LilRAE as one product across a rename and proposes a broader capability
ownership model. It remains proposed. This ADR records only the completed
repository and name change and the limited naming transition; it does not
accept ADR-054 or claim that its migration work is complete.

## Decision

LilRAE is the project's name. APTL is its former name. They identify one
project; there is no second backend, wrapper, or product layer.

### Limited public naming transition

The transition changes only the public entry points needed for users to
recognize LilRAE, and explains the legacy name where users still meet it:

| Surface | Change |
| --- | --- |
| `README.md` | Heading, introduction, safety lead sentence, and a prominent note explaining the move and rename and the retained package and command names. |
| `docs/index.md` | Heading, introduction, safety warning, the same rename note, and the install task label. |
| `docs/getting-started/installation.md` | Names LilRAE at the install step and explains why the package is `aptl-labs` and the command is `aptl`. |
| `mkdocs.yml` | Site title, site author, and the install navigation label. |

Other current pages, generated help, and interface text continue to say APTL
where they do. The rename note makes those occurrences unambiguous, so they
are not changed by this decision. Repository URLs belong to #1230.

### Retained compatibility identities

The rename does not change any executable or persisted identity, including:

- the `aptl-labs` distribution, the `aptl` import root, and the `aptl` and
  `aptl-misp-suricata-sync` commands;
- the `aptl.*` entry-point groups;
- `aptl.json`, configuration fields, `APTL_*` environment variables, and the
  `.aptl` state directory;
- container, image, network, volume, and label names, Compose project names,
  and backend target strings;
- schema identifiers, run records, archives, signatures, and evidence;
- CLI help text, web interface titles, API descriptions, and MCP server
  descriptions;
- quality-gate project keys and the `.ground-control.yaml` project identity.

A future change to any of these needs its own compatibility and migration
decision. No alias package, compatibility shim, second import root, duplicate
configuration schema, or name toggle is introduced.

### Naming convention for new code

Use `lilrae` as the naming convention for new code going forward. A new
top-level identity, such as a new module, package, service, environment
variable, resource name, or configuration file, uses `lilrae` (`LILRAE_` for
environment variables, LilRAE in prose).

When new code extends an existing interface, it follows that interface's
current identifiers. Code inside `src/aptl/` still imports through `aptl`.
Extensions register through the existing entry-point groups. New fields join
existing configuration models under their current names. A new identifier
that participates in an existing contract follows that contract rather than
introducing a parallel `lilrae` spelling.

The repository's planning rules in `.gc/plan-rules.md` carry
this convention as a mandatory plan constraint.

### Historical records

Accepted ADRs, preflight notes, review records, requirement history, changelog
entries, and evidence keep the names they were written with. Event listings
and talk titles accepted under the APTL name keep that name.

## Consequences

- Users arriving at the renamed repository or documentation site see LilRAE
  first and learn why commands still say `aptl`.
- Mixed naming remains on secondary pages and in technical identifiers. The
  rename note and this ADR explain it; a corpus-wide sweep is deliberately
  avoided.
- New code gains a single, stated naming rule without breaking existing
  installations or interfaces.
- Renaming the package, command, configuration, or runtime identities remains
  open work that requires its own decision, release, and migration guidance.
