# Issue #1232: LilRAE Naming Preflight

Issue #1232 is the contract. It records the transfer and rename of the existing
project to `OpenRAE/lilrae`, retaining source, history, features, and tracker.
This preflight constrains the upcoming documentation change; it leaves the
public naming edits, new ADR, and planning-rule amendment to implementation.

## Identity And Compatibility Boundaries

Use **LilRAE** as the public project name and **`lilrae`** as the convention for
new code. APTL and LilRAE describe one project's continuity. The transfer does
not establish a second backend, wrapper, product layer, or new security model.
[ADR-054](../adrs/adr-054-lilrae-core-and-experience-ownership.md) already
describes that continuity and remains proposed. The new ADR required by #1232
records the completed repository/name change and limited naming policy. It
must not accept ADR-054 implicitly, supersede its capability-ownership design,
or claim its broader migration work is complete.

The forward naming rule needs an explicit compatibility exception in both the
new ADR and `.gc/plan-rules.md`: extending an existing interface follows that
interface's current names. New implementation inside `src/aptl/` still imports
through `aptl`; extensions use the existing entry-point groups. A new private
identifier can follow `lilrae` without creating a second import root, config
model, or service. A new public identifier that participates in an existing
contract must follow that contract. Future contract renames require separately
authorized compatibility and migration decisions.

## Minimal Public Scope And Canonical Owners

| Surface | Boundary and existing owner |
| --- | --- |
| GitHub and package-index gateway | `README.md` supplies the package readme through `pyproject.toml`. Its heading, introduction, prominent rename note, and current project references should identify LilRAE and explain APTL. Keep the short install journey and safety warnings intact. Historical event titles and their external URLs retain their recorded names. |
| Published task hub | `docs/index.md` should make the same identity and compatibility explanation visible independently of the README. Preserve direct operator-task links and the distinction between operator, target, and SOC interfaces. |
| Site identity and navigation | `mkdocs.yml` owns `site_name`, `site_author`, navigation labels, and the Decisions tree. Update public identity there and link the new ADR from `docs/adrs/README.md` and relevant navigation. Keep file locators and task order stable. |
| Immediate installation handoff | The current landing-page link and MkDocs label say “Install APTL”; `docs/getting-started/installation.md` also says “install APTL.” These are justified additional naming edits. Explain the retained package/command names at this handoff; preserve every executable example. Other entry pages, including `CONTRIBUTING.md` and `SUPPORT.md`, need edits only where an unexplained old identity confuses the chosen journey. Record that selection in the ADR and PR. |
| Decision and planning policy | Follow ADR-000's sequential numbering, status/date/context/decision/consequences format and index convention. ADR-061 is the current highest number; check again before choosing the next. `.ground-control.yaml` already points `rules.plan_rules` to `.gc/plan-rules.md`. Add the naming rule there with a repository-relative ADR link; retain the existing config shape and planning constraints. |
| Location and publishing | Related #1230 owns repository-location wiring. This checkout still contains legacy repository links and metadata. Coordinate any overlapping link changes with that issue. ADR-038 explicitly keeps the legacy GitHub Pages URL canonical, with Read the Docs as a mirror; a repository transfer alone does not prove a new docs host, badge project, or release endpoint exists. |

The README note must state that the existing project moved and was renamed,
and explain why users still install `aptl-labs` and execute `aptl`. APTL need
not disappear from every current page for that explanation to be consistent.
Avoid expanding the PR into a corpus-wide terminology sweep.

## Cross-Cutting Passage

This design introduces prose and planning policy, with no new runtime input.
Examples and claims must continue to fit the following existing layers.

| Layer | Incumbent and required fit |
| --- | --- |
| Package, CLI, and supply chain | `pyproject.toml` owns `aptl-labs`, `aptl`, `aptl-misp-suricata-sync`, and the `aptl.*` entry-point groups. `hatch_build.py`, `_asset_manifest.py`, locked requirements, and release-please consume those identities. Keep them unchanged; do not advertise an unshipped `pipx install lilrae` or `lilrae` executable. |
| Config shapes and environment binding | `core/config.py` owns `AptlConfig`, nested `extra="forbid"` models, `ScenarioSourceConfig`, and `load_config()`. `core/env.py`, placeholder checks, host-port validation, `api/deps.py:WebAuthSettings`, and `services/misp_suricata_sync/config.py:ServiceConfig` own environment inputs. `mcp/aptl-mcp-common/src/config.ts` owns shared JSON/dotenv loading; its `LabConfig` interface is compile-time typing with shallow runtime checks. Preserve `aptl.json`, existing fields and `APTL_*` names. Do not invent alias keys, a naming parser, or per-server validation. |
| Admission and filesystem | `core/scenario_bundle.py`, scenario catalog admission, RAES contracts, env-pack validation, and `utils/pathsafe.py` own content identities and containment. Documentation does not change their accepted shapes, paths, digests, or authority. |
| Authentication and network | `api/deps.py:verify_token`, `api/session.py`, BFF Host/CSRF/session gates, terminal tickets, and MCP common API/TLS policy remain authoritative. Retain loopback defaults, runtime discovery through `aptl lab info`, direct-host exposure warnings, and disposable-seat limitations. Naming conveys no new isolation guarantee. |
| Secrets and OS exposure | ADR-029 and Python/MCP redaction helpers own secret handling. Use credential locations rather than values. Do not inspect secret stores or generated `.env`, `.mcp.json`, `.aptl`, keys, or runs to research naming. Add no secret-bearing argv, environment dumps, public login URLs, or diagnostic transcripts. No host service, Docker action, socket, or privilege change is needed. |
| Errors and observability | RAES diagnostics, `core/lab_types.py:LabResult` and `StartupDiagnostic`, typed API responses, domain exceptions, and common MCP handlers own outcomes. `utils/logging.py:get_logger()`, redaction, and common telemetry own reporting. Preserve diagnostic codes, error envelopes, logger namespaces, and telemetry keys. Do not duplicate exception trees or expose raw validation input/backend stderr in prose. |
| Persistence and native identity | `core/runstore.py`, `core/archival/`, provenance/correlation models, `backends/identity.py`, deployment configuration, and appliance records own state and runtime identities. Preserve `.aptl`, schema IDs, labels, container/network/image names, backend target strings, signatures, and historical evidence bytes. A public name is not a resource-ownership predicate. |
| Workflow and documentation validation | `.ground-control.yaml`, `.gc/plan-rules.md`, `.pre-commit-config.yaml`, `.vale.ini`, and `.github/workflows/checks.yml` remain the gates. Both `.github/workflows/docs-deploy.yml` and `.readthedocs.yaml` consume the same `mkdocs.yml` and hash-locked `requirements/docs.txt`. Add no parallel naming workflow, navigation schema, or documentation build. |

## Verification Gotchas And Extension Seam

`tests/test_docs_user_journey.py` hardcodes the “Install APTL” link label and
legacy repository policy URLs. Update expectations only for deliberate label
or coordinated URL changes, retaining checks on task destinations and private
vulnerability reporting. Reuse its structural checks rather than adding a
second docs parser or tests that merely count brand strings.

`tests/test_scenario_pack_ownership_contract.py` inventories current prose
containing pack terminology against the
[issue #592 inventory](issue-592-scenario-pack-terminology-preflight.md).
This note belongs in that inventory. If the new ADR uses those terms, inventory
it too; preserve the RAES/env-packs/backend ownership boundary.

MkDocs configuration contains a Python-tagged SuperFences formatter. Follow
the existing test's explicit normalization when using `yaml.safe_load()`;
do not load arbitrary YAML unsafely in a new validator. Changed headings can
alter fragment links even when filenames stay unchanged. Check inbound local
links and keep stable locators. Relative ADR links from `.gc/plan-rules.md`
must resolve from `.gc/`, rather than from `docs/`.

Local verification stays scoped: explicit affected test paths through
`bash tools/run-targeted-tests.sh`, plus `pre-commit run` after staging intended
files. Whole-corpus Vale and `mkdocs build --strict` belong to CI/CD under the
current rules. Local pre-commit currently runs fast hygiene and secret checks,
not Vale, tests, or a site build; ADR-038's older hook wording is not the current
command contract. Do not weaken checks or rewrite unrelated historical prose
to make a naming change pass.

The extension seam is the separation already present in site metadata,
packaging/CLI contracts, and the linked naming policy. Change display metadata
without routing executable behavior through it. Keep the rule in the one
Ground Control planning artifact, linked to its ADR. A future package or CLI
cutover can use the existing packaging and command-registration seams after
its own compatibility decision; no brand registry, environment toggle, wrapper,
or alias matrix is warranted here.

## Non-Goals

No repository-wide code rename, runtime or frontend rebranding, new import
namespace, compatibility shim, feature removal, lifecycle refactor, data
migration, historical-record rewrite, release/version/changelog edit, hosting
move, or external account reconfiguration. No formal requirement exists for
this run: use issue #1232 as the contract without fabricating a Ground Control
UID, traceability record, or requirement-status transition.
