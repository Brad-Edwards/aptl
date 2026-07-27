# Issue 847 OpenSSF Scorecard Preflight

This note fixes the architecture guardrails for adopting OpenSSF Scorecard. It
is design guidance, not an implementation plan. ADR-010 remains authoritative
for the hard SonarCloud quality gate, and ADR-026 remains authoritative for
dependency and vulnerability scanning.

## Architecture Decisions

- Run Scorecard in a dedicated GitHub Actions workflow. This is the concrete
  exception to ADR-026's preference for the shared `Checks` workflow:
  publishing results imposes a restricted workflow and job shape that the
  multi-job checks workflow cannot satisfy.
- Use only supported default-branch `push` and weekly `schedule` triggers.
  APTL's default branch is `main`. Do not use `pull_request_target`, run
  untrusted pull-request code, or expand the publisher to `dev` or feature
  branches. Pull-request and manual triggers are experimental upstream and do
  not establish the authoritative published result.
- Start from read-only workflow permissions and grant `id-token: write` only
  on the Scorecard job. Grant `security-events: write` on that job only because
  this design intentionally makes GitHub Code Scanning the durable alert
  surface. No workflow-level write permission is allowed.
- Use GitHub's ephemeral Ubuntu-hosted runner and the upstream publisher's
  approved action set only: `actions/checkout`, `ossf/scorecard-action`,
  `actions/upload-artifact`, and `github/codeql-action/upload-sarif`. Pin every
  action to a full commit SHA, retain the human-readable release comment, and
  set `persist-credentials: false` on checkout.
- Publish SARIF to three existing external surfaces with distinct purposes:
  the short-retention Actions artifact is diagnostic evidence, Code Scanning is
  the maintainer alert queue, and `api.scorecard.dev` is the public result
  consumed by the README badge. Do not add a repository-local result database,
  parser, DTO, or exception hierarchy.
- Treat Scorecard as a repository and supply chain posture assessment, not as a
  replacement for the vulnerability scanners in `checks.yml`. Its aggregate
  score is not a merge gate and is not itself a vulnerability count.

The first authoritative `publish_results: true` run exists only after the
workflow reaches `main`. A feature-branch or local preview cannot prove that
publishing, OIDC, Code Scanning upload, and the badge work. Completion evidence
must therefore include a successful default-branch run and its published
result; do not weaken the trigger or token boundary to avoid this bootstrap
constraint.

## Existing Concerns To Reuse

| Concern | Canonical owner and required reuse |
|---|---|
| Workflow security | `.github/workflows/*.yml` owns top-level read-only defaults, job-local write elevation, SHA-pinned actions, trusted triggers, and non-interpolation of untrusted event data. |
| Action maintenance | `.github/dependabot.yml` is the only GitHub Action update mechanism. The new action pins must be covered by its existing `github-actions` entry; do not add Renovate or a manual version file. |
| Vulnerability authority | `dependency-audit`, `osv-scanner`, and the Trivy filesystem, IaC, and image jobs in `.github/workflows/checks.yml`, governed by ADR-026, remain the detailed scanners and evidence producers. |
| Dependency shapes | `pyproject.toml` plus `uv.lock`, every package's `package.json` plus `package-lock.json`, and Dockerfiles/base-image references are the canonical dependency declarations. Remediation changes those owners and regenerates their existing locks; it does not add a Scorecard-specific dependency schema. |
| Release supply chain | `.github/workflows/release-please.yml` owns PyPI OIDC publication, release assets, and the CycloneDX SBOM. A Scorecard finding does not create a second publisher or SBOM path. |
| Static analysis and tests | SonarCloud, pre-commit, pytest, vitest, strict MkDocs, and Vale retain their current gate semantics. Scorecard does not duplicate their validation or become a required PR check. |
| Security reporting | `SECURITY.md` remains the human vulnerability-reporting contract. Code Scanning owns machine-generated Scorecard alerts; public issues remain the wrong place for vulnerability details. |
| Branch policy | Live GitHub repository rules are authoritative. `.github/branch-protection-baseline.json` documents required checks but cannot prove that the live rules match; editing the JSON alone is not remediation. |

## Finding And Vulnerability Boundary

Every result must be triaged at the individual check/detail level, not from the
badge's aggregate score.

- A true positive from Scorecard's `Vulnerabilities` check is unresolved until
  the affected first-party code or dependency is updated, removed, or otherwise
  made non-vulnerable and a fresh authoritative run no longer reports it.
- Intentional lab behavior is not permission to retain an accidentally
  vulnerable dependency, build tool, action, or base image. Deliberate scenario
  weaknesses should remain explicit application/configuration fixtures, not
  stale supply chain components.
- A false positive or non-applicable advisory needs a specific evidence-backed
  rationale tied to the finding. Do not add a blanket ignore, suppress an
  entire check, or call a low score “fixed.”
- Non-vulnerability checks such as Contributors, CII Best Practices, Fuzzing,
  Signed Releases, or Branch Protection describe different risks and facts.
  Remediate repository-owned actionable weaknesses, but do not invent
  contributors, conflate test strategy with fuzzing, or change live policy only
  to maximize the aggregate score.
- Resolve overlapping dependency findings through the existing package
  manifest/lock and scanner owners. Do not make Scorecard, OSV, pip-audit, npm
  audit, and Trivy each maintain separate exceptions for the same fact.

## Security And Validation Passage

| Layer | Required behavior |
|---|---|
| GitHub workflow shape | The YAML must pass the repository's existing YAML/pre-commit checks and Scorecard's stricter publisher validation: no top-level or job-level `env`/`defaults`, no workflow-level write permission, no container/services, an Ubuntu-hosted runner, and only approved actions in the publishing job. |
| Authentication | Use the automatic `GITHUB_TOKEN`; do not add a PAT or repository secret. Its default access is read-only. `security-events: write` and `id-token: write` are scoped to the single publishing job. |
| OIDC and secret handling | OIDC exists only to authenticate result publication. Let GitHub and the action exchange the token through the Actions runtime; never put a token, JWT, repository secret, or full GitHub context in inputs, shell text, process arguments, artifacts, or logs. |
| Source checkout | Checkout only trusted `main` commits from supported events and disable persisted credentials. The job executes no repository script and no dependency installer, so checked-out content cannot turn the job's write/OIDC capabilities into arbitrary code execution. |
| Result shape and persistence | `ossf/scorecard-action` is the sole Scorecard result producer. Emit SARIF to a fixed filename, upload that exact file through the official artifact and CodeQL upload actions, and use short retention. Do not post-process untrusted SARIF in a shell. |
| External publication | `publish_results: true` deliberately makes repository posture public at `api.scorecard.dev`. The README uses the canonical project-specific badge/viewer URLs; it does not cache a score or encode a threshold. |
| OS/runtime exposure | Run only on an ephemeral GitHub-hosted Ubuntu runner, with no service, container, self-hosted runner, network listener, host mount, or lab startup. The OIDC token is not exposed through process `argv`; checkout credentials are not left in `.git/config`. |
| Errors and observability | Action failure, SARIF upload failure, and publication rejection must fail the workflow visibly. Findings flow to Code Scanning, the artifact, action logs, and the public API. Do not swallow errors, scrape logs, or route these through APTL's application error envelopes, `get_logger()`, or OpenTelemetry. |
| Product validators | `AptlConfig`, environment hydration, API authentication/CSRF, SDL/Pydantic validation, container policy, run-store persistence, and application redaction are not traversed because this workflow adds no product input, config, process, route, listener, or runtime state. Do not create adapters to make them appear involved. |

## Extensibility And Whole-Repository Scope

The extensibility seam is the action's explicit SARIF output, not a custom
Scorecard wrapper. A future policy gate can consume the versioned SARIF or Code
Scanning result in a separately designed, PR-compatible trust boundary without
changing the publisher job. The explicit schedule, `main` trigger, result
filename/format, artifact retention, and action SHA are the only operational
knobs needed now; Dependabot owns future action-pin updates.

The repository surfaces in scope are:

- the dedicated workflow and GitHub-hosted runner/OIDC/Code Scanning services;
- the README badge;
- the existing action pins and Dependabot action-update configuration;
- live repository rules plus their checked-in branch-protection baseline;
- `SECURITY.md`, ADR-010, and ADR-026;
- Python, Node, container, workflow, and release dependency declarations when
  an actual finding requires remediation;
- the release workflow, SBOM, existing scanners, pre-commit, tests, and docs
  gates used to verify any resulting repository change.

## Gotchas And Anti-Patterns

- Do not place the publishing job in `checks.yml`; its unrelated steps, jobs,
  and permissions make the Scorecard publisher contract fragile.
- Do not grant `id-token: write` or `security-events: write` at workflow scope,
  use `write-all`, add a PAT, or persist checkout credentials.
- Do not add repository scripts, arbitrary shell steps, package installers,
  containers, services, or unapproved actions to the publishing job.
- Do not use a tag such as `@v2`; full SHA pinning plus Dependabot is the
  repository's supply chain convention.
- Do not use `pull_request_target`, interpolate event payloads into a shell, or
  execute pull-request code with the publisher's write/OIDC permissions.
- Do not make a scheduled/default-branch job a required pull-request check; it
  cannot reliably produce a PR status. A future gating design needs a separate
  PR-compatible contract.
- Do not treat a badge change, aggregate-score increase, suppressed result, or
  edited branch-protection baseline as proof that a vulnerability is fixed.
- Do not “fix” intentional lab exercises by removing their designed weakness
  while leaving vulnerable dependencies in place. Preserve the scenario
  contract and repair the supply chain component.

## Non-Goals And Boundaries

This issue does not add an APTL runtime feature, config/environment key, API,
DTO, service, repository, database, exception type, logger, telemetry signal,
container, listener, or host process. It does not replace SonarCloud, Trivy,
OSV-scanner, pip-audit, npm audit, Dependabot, the release SBOM, or
`SECURITY.md`. It does not make Scorecard a merge gate, guarantee a score of
10, manufacture project-governance facts, adopt a second dependency-update
tool, or redesign release signing, fuzzing, branch governance, and packaging
unless a concrete reported weakness is separately accepted into scope.
