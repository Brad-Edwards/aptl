# Issue #969 Platform Safety Gates Preflight

This note fixes the architecture boundary for the required `dev` pull-request
checks in issue #969. It is design guidance, not an implementation plan.
ADR-026 still owns advisory Trivy and OSV scanning, while proposed ADR-058
defines the platform-versus-intentional-target distinction that this issue
applies. No new product architecture or qualification framework is needed.

## Architecture Decisions

### Gate the platform through the existing jobs

The platform-safety set is the existing `Pre-commit hooks`, `Python tests +
coverage`, `MCP TypeScript tests + coverage`, `Dependency vulnerability scan`,
and `Clean-install lab boot and teardown (DEP-008)` job contexts. Keep their job
names stable because GitHub branch protection binds to the emitted context
strings. Other established governance or quality checks are separate policy;
issue #969 does not justify silently removing them.

Keep these jobs in `.github/workflows/checks.yml`. Do not add a second workflow,
aggregate wrapper job, path-filtered shadow gate, or release-only qualification
pipeline. A wrapper would hide which contract failed and create another status
whose success and skip semantics must be maintained.

`.github/branch-protection-baseline.json` is the checked-in record of intended
policy. Live GitHub branch protection or rulesets are the enforcement authority.
Changing workflow YAML makes a check run, and changing the baseline documents
intent; neither makes the check required. Apply the contexts through the same
repository settings route used by issues #502 and #852, then read the live
`dev` rule back and compare exact context names. Do not add an administrative
workflow, PAT, or self-mutating Actions job to manage branch protection.

### Split platform dependencies from intentional target weaknesses

Blocking dependency audit scope is the code APTL ships and trusts with operator
credentials or control-plane authority:

- the CLI/runtime closure exported as `requirements/runtime.txt`;
- the API closure exported as `requirements/web.txt`;
- the CI/build closure exported as `requirements/ci.txt`, because it constructs
  the wheel and release evidence even though it is not installed for users;
- the production dependency closure in every `mcp/*/package.json` and its
  adjacent `package-lock.json`; and
- the shipped web package when its production dependencies are covered by the
  existing platform audit job.

Audit those canonical exports and locks directly. Do not infer the shipped
Python closure from whichever tools happen to share the audit virtual
environment: the CI/build export is a separately named platform surface, not a
substitute for the runtime/API dependency shapes. Point `pip-audit` at the
exports instead of installing the checkout editable; the latter executes the
pull request's build hook and audits an ambient mixture. For Node, validate each
manifest/lock pair without lifecycle scripts and audit production dependencies
at the repository's existing `high` threshold. Package discovery starts from
`package.json`; the empty historical `mcp/package-lock.json`, which has no
adjacent manifest, is not another package. An install or lock mismatch, scanner
failure, or unscanned discovered MCP manifest also fails the job; an
unconditional final `true`, broad `set +e`, or `continue-on-error` would turn a
required context into false assurance.

Intentional target behavior remains in the advisory Trivy filesystem, image,
and IaC surfaces governed by ADR-026. A target's purpose never exempts a
dependency in the CLI, API, web control plane, MCP common library, MCP server,
CI build path, or release path. Conversely, do not make the platform dependency
gate parse scenario content or classify Trivy findings.

When the blocking platform policy lands, add a dated amendment to ADR-026 so it
no longer describes the whole dependency-audit job as advisory. Preserve its
accepted advisory decision for mixed target image/filesystem/IaC findings and
its Scorecard amendment. Do not mark proposed ADR-058 accepted as an incidental
CI edit; that status requires its own architecture decision.

A temporary platform exception must stay scanner-native and adjacent to the
canonical audit command or affected manifest. Prefer a patched dependency or a
narrow manifest `overrides` entry, following `web/package.json`, over accepting
a finding. If acceptance is unavoidable, record the advisory identifier,
ecosystem package and version, affected APTL component, concrete reason, owner,
expiry/removal condition, and the scanner's exact narrow exclusion. Do not
invent an exception registry before a real exception exists; `npm audit` has no
native per-advisory ignore, so its limitation is not grounds for broad exit-code
suppression. Never add a blanket cyber-range exception, suppress a package
family, lower the global threshold, or copy one exception into several
scanner-specific allowlists. Intentional target findings need no platform
exception because they are outside this blocking dependency surface.

### Repair the installed-wheel smoke contract in place

`clean-install-lab-boot` is the sole installed-artifact lifecycle smoke. Keep
the existing product-neutral `materialization-envelope.sdl.yaml` scenario and
the public sequence: build the wheel with the locked toolchain, install it with
locked runtime dependencies into a clean virtual environment, run `aptl lab
init`, start the scenario, prove a native container effect, stop with volumes,
and prove project-scoped cleanup.

The native effect is read from the running container, not inferred from CLI
success or generated Compose. Resolve the container by the validated
`deployment.project_name` Compose label together with the admitted
`aptl.node.address` label, and require exactly one match before `docker exec`;
another project must not be able to satisfy the assertion. The existing
package, local identity, and filesystem checks all exercise one small
realization envelope; retain a minimal representative assertion set rather than
adding TechVault services or a second smoke scenario. Teardown runs after every
outcome and fails when absence cannot be proved.

This gate supports the **generic installed-wheel materialization and lifecycle
profile on a GitHub-hosted Ubuntu Docker runner**. It establishes packaging,
admission, one native realization effect, status, stop, and cleanup for that
bounded profile. It does not qualify TechVault, LilRAE, a participant journey,
telemetry parity, remote Docker, Windows/macOS lab boot, or release adoption.
Those broader journeys remain with APTL #870/#685 and OpenRAE/lilrae #4/#9/#10.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| CI workflow | `.github/workflows/checks.yml` owns the existing jobs, least-privilege workflow permissions, SHA-pinned actions, locked installs, artifacts, and job context names. Extend these jobs; do not duplicate them. |
| Branch governance | Live GitHub branch protection/rulesets enforce required contexts. `.github/branch-protection-baseline.json` records the verified intended state, and `.github/workflows/pr-title-lint.yml` demonstrates that a running workflow and a required context are distinct contracts. |
| Python dependency shapes | `pyproject.toml` and `uv.lock` are authoritative; `.pre-commit-ci.yaml` generates hash-verified `requirements/runtime.txt`, `requirements/web.txt`, and `requirements/ci.txt`. Audit each named install/build surface directly rather than inventing another manifest or dependency DTO. |
| Node dependency shapes | Each `web`/MCP `package.json` plus adjacent `package-lock.json`, installed with `npm ci`, is authoritative. Discover `mcp/*/package.json` so a future server cannot silently escape audit; do not create a hand-maintained second MCP inventory. |
| MCP build/test coupling | `mcp/aptl-mcp-common`, every consuming MCP package, `mcp/build-all-mcps.sh`, and the `mcp-tests` job own common-first builds and consumer compatibility. Dependency audit does not replace builds, vitest, or transport tests. |
| Advisory scanners | ADR-026 and the existing Trivy filesystem/IaC/image and OSV jobs own broad target, image, lockfile, and posture signal. Keep their artifact-only/advisory semantics instead of feeding their mixed findings into the platform gate. |
| Installed artifact | `hatch_build.py`, `_asset_manifest.py`, locked requirements, `aptl.core.assets.materialize()`, and the public `aptl lab init/start/status/stop` commands own wheel construction and lifecycle behavior. |
| Scenario admission | `tests/fixtures/materialization-envelope.sdl.yaml`, the existing scenario resolver, RAES parse/plan/admission, `AptlProvisioner`, and `DeploymentBackend` own the smoke model and its realization. No CI-only scenario schema or backend path. |
| Cleanup identity | Strict `AptlConfig`, validated `deployment.project_name`, `observe_project_runtime()`, and `project_scoped_volume_names()` own the project-bounded absence proof in `scripts/ci/assert_project_teardown.py`. |
| Secrets, diagnostics, and logs | `hydrate_dotenv()`, `EnvVars`, ADR-029, `redact()`, `LabResult`/startup diagnostics, and `get_logger()` remain the product boundaries. Actions logs and job conclusions remain the CI observability surface. |
| Supply chain validation | `tests/test_supply_chain_pinning.py`, `tests/test_hashed_requirements.py`, pre-commit, Dependabot, and the release workflow retain action, Python, Node, image, build, and publication pinning rules. |
| Workflow contract tests | `tests/test_promotion_workflow.py` owns the checks-workflow trigger/job-presence pattern; `tests/test_scenarios.py` owns the clean-install fixture/CLI contract; `tests/test_consistency.py` owns MCP build-list completeness. Extend these structural contracts instead of adding a second CI policy test framework. |

## Security And Cross-Cutting Passage

| Layer | Required behavior |
| --- | --- |
| GitHub authentication and policy | Pull-request jobs use the existing read-only `GITHUB_TOKEN` boundary and never need a PAT or write permission. A maintainer applies branch policy outside untrusted PR execution and verifies the live `dev` rule by exact context name. Do not expose administrative credentials to Actions. |
| Workflow/input shape | Existing YAML/pre-commit and supply chain tests validate workflow syntax conventions, action pins, and locked install forms. Keep `pull_request` rather than `pull_request_target`; do not interpolate branch, title, manifest content, or scanner output into shell commands. Repository-controlled package paths may be passed as quoted arguments. |
| Dependency validation | Python passes through `pyproject.toml` -> `uv.lock` -> generated hashed runtime/web/CI exports -> direct `pip-audit` inputs. Node passes through `package.json` -> adjacent lock -> script-free lock validation -> production `npm audit`. Scanner errors and incomplete package discovery fail closed. No duplicate parser, schema, or exception hierarchy is warranted. |
| Product auth surface | Dependency scans add no endpoint. The smoke invokes only the local CLI and does not exercise or weaken API token, Host, CSRF, browser-session, or MCP caller-grant checks. Native container inspection is runner-side and never becomes a product API. |
| Product config and scenario shape | The clean lab starts from `aptl lab init`; `aptl.json` passes strict Pydantic models with `extra="forbid"`, the project name validator bounds Docker identity, and the smoke SDL passes the existing RAES parser/compiler/planner and backend model validation. Add no CI flag, service allowlist, or alternate schema. |
| Secrets and environment | Lab-start hydration may create `.env`, keys, and generated credentials with their existing ownership rules. Do not print, upload, cache, or pass those values in process arguments; keep shell tracing off. Scanner inputs are public manifests/locks and need no product or repository secret. |
| OS/runtime exposure | Scans run on an ephemeral hosted runner with no listener and no product/repository secret. Do not execute the checkout through an editable Python install or npm lifecycle hook merely to inspect locks. The smoke alone reaches its local Docker daemon and creates one internal-network lab. Preserve list-form CLI/Docker invocation, validated project-scoped identity, two-label container selection, bounded waits, and cleanup; never use daemon-wide prune or broad `aptl-*` name matching. |
| Error envelopes and observability | Scanner exit status and bounded tool output belong to the Actions job. Product failures retain `LabResult`/startup diagnostics and redaction. Do not dump raw environment, generated project state, Docker inspection, credentials, or tracebacks merely to make CI diagnosable; do not add a CI exception class, API response, OTel signal, or persistence record. |
| Persistence | GitHub owns check conclusions and live branch policy. Short-retention advisory SARIF stays where ADR-026 puts it. The smoke may create only its temporary project and Docker resources, all of which must be removed; no qualification database or committed result file is introduced. |

## Extensibility And Whole-Repository Scope

The dependency-audit seam is **canonical manifest discovery plus production
scope**: generated Python runtime/API exports and every adjacent-lock MCP/web
manifest. A future MCP package is covered by the `mcp/*/package.json` discovery
boundary without editing a second package registry. A future separately shipped
Python extra belongs in its own generated hash export and can be added as one
explicit audit input without changing scanner policy.

The smoke seam is the selected small SDL path and native assertion set in the
existing job. A future generic realization effect can replace or extend that
fixture only when it remains one bounded installed-wheel scenario; scenario
specific qualification belongs behind its adapter and separate journey gate.
Branch-policy extensibility is the stable job `name` plus the baseline's context
array, always verified against the live rule rather than inferred from files.

The whole-repository surfaces in scope are:

- `.github/workflows/checks.yml`, the exact emitted job names, live `dev` branch
  rules, and `.github/branch-protection-baseline.json`;
- `pyproject.toml`, `uv.lock`, `.pre-commit-ci.yaml`, generated runtime/web/CI
  requirements, `web/package*.json`, and every manifest-backed
  `mcp/*/package*.json`;
- ADR-026, ADR-058, supply chain tests, Dependabot, and release dependency/SBOM
  surfaces;
- `hatch_build.py`, packaged asset inventory, public lab CLI/core orchestration,
  strict config/env hydration, RAES admission/materialization, and deployment
  backend validation;
- the smoke SDL, clean temporary virtual environment/project, hosted Ubuntu
  runner, local Docker daemon, project containers/networks/volumes, and
  project-scoped teardown assertion.

## Gotchas And Anti-Patterns

- Do not treat workflow presence or the checked-in baseline as proof of live
  protection. Verify the server-side rule after applying it.
- Do not rename a required job casually; the old required context can become
  permanently pending while the new job remains optional.
- Do not swallow `npm ci`, audit, or tool failures while making findings
  blocking. Advisory target scans and blocking platform audits must remain
  visibly distinct.
- Do not audit the ambient Python environment and mistake CI-tool findings for
  the shipped CLI/API closure, omit the separately named CI/build surface, or
  omit the API export because runtime currently overlaps it.
- Do not execute the pull request's Hatch build hook, npm `prepare`, or other
  package scripts as a side effect of reading dependency locks.
- Do not maintain a second list of MCP packages, a duplicate dependency schema,
  a custom vulnerability parser, or parallel exception files per scanner.
- Do not label a control-plane dependency vulnerability intentional because
  APTL contains vulnerable targets. Scope follows component authority, not the
  repository's security-lab purpose.
- Do not turn the installed-wheel smoke into a TechVault boot, participant
  walkthrough, conformance suite, or cache-dependent release rehearsal.
- Do not use editable/source installs, the checkout's CLI, generated developer
  state, or separately installed scenario adapters in the wheel smoke.
- Do not accept CLI success, container `Up`, or generated Compose text as the
  native effect. Inspect exactly one running container selected by both its
  admitted node label and validated project label.
- Do not make cleanup best-effort, check only running containers, delete by
  broad prefix, or prune the Docker daemon. Observation failure is a failed
  absence proof.

## Non-Goals And Boundaries

Issue #969 does not redesign application auth, API/MCP DTOs, config, RAES or SDL
schemas, deployment backends, lifecycle results, exception hierarchies,
logging, telemetry, or persistence. It does not add a scanner service, policy
engine, vulnerability database, qualification report schema, release workflow,
or second smoke framework.

It does not make intentional target/container findings blocking, remove
designed scenario weaknesses, qualify full TechVault or LilRAE journeys, claim
cross-platform Docker support, or replace #870, #685, and OpenRAE/lilrae
#4/#9/#10. It does not merge a pull request or change branch protection merely
by editing repository files; live governance remains a separately verified
server-side action.
