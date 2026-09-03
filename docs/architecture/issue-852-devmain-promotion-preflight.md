# Issues 852 And 940 Dev-To-Main Promotion Preflight

This note fixes the design boundaries for standardizing the `dev` to `main`
promotion and for recognizing that exact branch pair in repository-side PR
policy. It is architecture guidance, not an implementation plan.
`docs/releasing.md` remains the operator-facing release contract.

## Architecture Decisions

- Keep promotion as a repository workflow operation. The existing `Makefile`
  may expose the convenience entry point, but it must delegate PR creation to
  GitHub CLI with explicit `dev` head and `main` base branches. Do not add an
  APTL CLI command, Python service, configuration key, or release abstraction.
- Fix the promotion title and warning text at the entry point:
  `chore(main): promote dev`, with a PR body that says to use a merge commit and
  not squash. These values are policy, not user-configurable presentation.
- Treat the target as a PR creator, not a merge controller. The target cannot
  guarantee how a maintainer later merges the PR. The documented merge rule and
  live GitHub branch/ruleset configuration are the enforcement surfaces.
- Let `gh pr create` and GitHub remain authoritative for repository identity,
  branch existence, compare state, authentication, duplicate PRs, and whether
  the branches contain a promotable difference. Propagate failure unchanged.
  Do not use potentially stale local refs as a second ahead/behind validator or
  hide an empty-PR error with a successful exit.
- Extend the existing title workflow to both protected branches without
  changing its trust boundary: `pull_request`, read-only contents permission,
  SHA-pinned actions, checkout of the base SHA, and title parsing from
  `GITHUB_EVENT_PATH`. Never switch this policy job to
  `pull_request_target` or interpolate the event title into shell.
- Keep `tools/check_pr_title.py` as the single title-policy implementation.
  Contract tests should cover the exact promotion, Release Please, and
  back-merge title shapes. Do not copy its Conventional Commit regex or allowed
  types into Make, workflow YAML, or release code.
- Keep promotion identity separate from the exceptional title it permits. The
  trusted promotion class is the conjunction of base repository, head
  repository, base ref, and head ref. Only after that identity matches may the
  title policy accept GitHub's exact platform-generated `Dev` title. Do not use
  title text to establish promotion identity, and do not let promotion identity
  exempt arbitrary titles.
- The audit of repository PR workflows finds no other feature-PR-only metadata
  rule. `.github/workflows/checks.yml` has no title, body, label, author, draft,
  or changed-file condition and therefore needs no promotion branch. Keep its
  build, test, documentation, dependency, security, and supply chain jobs on
  both `main`- and `dev`-targeted pull requests.
- Make the operator documentation distinguish feature integration from
  promotion: feature PRs into `dev` are squash-merged, while the batch
  promotion from `dev` into `main` requires a merge commit. The merge preserves
  the individual Conventional Commit subjects that Release Please reads.

No ADR is needed. This change applies the existing release and CI trust
boundaries and does not introduce a durable product architecture decision.

## Existing Concerns To Reuse

| Concern | Canonical owner and required reuse |
|---|---|
| Promotion entry point | `Makefile` owns the repository convenience target. Keep `.PHONY` accurate and use the existing GitHub CLI rather than adding a wrapper package. |
| Title policy | `tools/check_pr_title.py` owns parsing, allowed types, stable violation IDs, and fail-closed event loading. `tests/test_pr_title_guard.py` owns its executable contract. |
| Title workflow trust | `.github/workflows/pr-title-lint.yml` owns triggers, least privilege, trusted-base checkout, action pins, concurrency, and safe event ingestion. |
| Release titles | `release-please-config.json`, the pinned Release Please action in `.github/workflows/release-please.yml`, and observed release commits own the release PR shape. Recent repository history contains `chore(main): release 5.0.0`, `5.1.0`, and `5.1.1`. |
| Back-merge titles | The `backmerge` job in `.github/workflows/release-please.yml` owns `chore: back-merge <tag> into dev`; do not create a second title formatter. |
| Release semantics | `docs/releasing.md` is the operator contract; `CONTRIBUTING.md` and `.gc/plan-rules.md` remain the contributor-facing Conventional Commit policy. |
| Branch governance | Live GitHub branch protection or rulesets are authoritative. `.github/branch-protection-baseline.json` is the checked-in record and must not be mistaken for enforcement. |
| Main-push consumers | Release Please, OpenSSF Scorecard, and docs deployment retain their existing `push` to `main` triggers. Promotion must not call or duplicate them. |
| Verification | `pytest`, strict MkDocs, Vale, pre-commit, and GitHub Actions syntax validation remain the existing gates. No issue-specific validation framework is needed. |

## Security And Validation Passage

| Layer | Required behavior |
|---|---|
| Developer authentication | Use the operator's existing `gh` authentication. Never embed a PAT, read a secret file, add a repository credential, or pass a token as a command argument. GitHub CLI and the API enforce repository permissions. |
| Local shell and process surface | Pass only fixed, non-secret branch, title, and body values. Explicit `--head` avoids implicit current-branch push/fork behavior. The PR text may appear in process arguments; no credential or environment dump may. Preserve the CLI's nonzero exit and stderr. |
| Repository and compare shape | GitHub CLI resolves the repository from its canonical local/`GH_REPO` mechanisms; GitHub validates base/head refs, differences, and duplicate PR state. A future friendly preflight, if justified, must query GitHub's compare API for that same resolved repository rather than inspect stale local tracking refs. |
| PR title shape | `tools/check_pr_title.py` validates untrusted event JSON, Conventional Commit type/scope/subject shape, lowercase subject, and branded-prefix policy. Promotion classification must use the exact four trusted identity fields before applying the one-title exception. The three workflow-produced title families must pass this function directly. |
| Workflow trust | Keep `pull_request`, base-SHA checkout, read-only permissions, pinned actions, and event-file parsing. A PR must not execute a policy checker from its own head or place its title in a `run:` expression. |
| Release configuration | The existing Release Please JSON schema and action remain unchanged. Promotion preserves commit topology; it does not synthesize changelog data or version state. |
| Branch rules | Adding `main` to the workflow filter makes a check run; it does not by itself make that check required. The checked-in baseline records `PR title lint` for both branches, but only the live rules can enforce it. Do not claim live enforcement from YAML or the baseline alone. |
| Bot-created PRs | Release Please and back-merge PRs use `GITHUB_TOKEN`. GitHub's current event rules can place resulting `pull_request` runs in an approval-required state. Keep the titles valid, but do not replace the token with a PAT merely to avoid approval or admin-bypass workflow. |
| Persistence and observability | GitHub owns the PR and git history. GitHub CLI stdout/stderr and the Actions check are the operational evidence. Do not add local state, a database record, APTL structured logging, OpenTelemetry, or a second error envelope. |
| Product validators | `AptlConfig`, environment hydration, API authentication/CSRF, SDL/Pydantic validation, container policy, redaction, and run-store persistence are not traversed because this change adds no product input, runtime, listener, or stored lab state. |
| Host and runner exposure | The target runs as a short-lived process on the developer host and reaches GitHub over the CLI's normal HTTPS path. The title check runs on a GitHub-hosted Ubuntu runner. No container, port, service, host mount, or lab startup is involved. |

## Extensibility And Whole-Repository Scope

The supported local-command extensibility seam is GitHub CLI's native repository
selection (`GH_REPO` or its `--repo` equivalent), not configurable promotion
branches or titles. In the title checker, keep repository/ref/title constants as
policy data and keep the event-object classifier callable independently of CLI
loading. `dev`, `main`, and the allowed titles remain repository policy. If a
second promotion pair is ever accepted, represent exact policy records and
match every field; do not generalize to target-branch, branch-name, owner-only,
or wildcard exemptions before real duplication exists.

The repository surfaces in scope are:

- `Makefile`;
- `.github/workflows/pr-title-lint.yml`;
- `tools/check_pr_title.py` and `tests/test_pr_title_guard.py`;
- `.github/workflows/release-please.yml` and `release-please-config.json`;
- `docs/releasing.md`, `CONTRIBUTING.md`, and `.gc/plan-rules.md`;
- live GitHub branch rules and `.github/branch-protection-baseline.json`;
- `.github/workflows/checks.yml`, `scorecard.yml`, and `docs-deploy.yml` as
  unchanged consumers of PRs or `main` pushes;
- the developer shell, GitHub CLI/API, Actions runner, and git commit graph.

## Gotchas And Anti-Patterns

- Do not squash the `dev` to `main` PR. A conventional promotion PR title makes
  the title gate pass; it does not make squash safe. Squash still collapses the
  batch of feature subjects Release Please needs.
- Do not conflate feature-PR squash policy with promotion merge policy, or
  describe all PRs as using one merge method.
- Do not conflate workflow coverage with required-check enforcement. Verify live
  branch governance separately and keep the baseline honest.
- Do not implement another Conventional Commit parser in Make, YAML, a shell
  script, or release configuration.
- Do not conflate "this event is the trusted promotion" with "this title is an
  allowed promotion title." Branch/repository identity establishes the former;
  the exact title comparison establishes the latter.
- Do not compute ahead/behind state from an unfetched local `main`, `dev`,
  `origin/main`, or `origin/dev`. Do not add an implicit fetch or mutate local
  branches merely to open a remote PR.
- Do not swallow `gh` failures, turn duplicate/empty/auth/network failures into
  success, or print authentication/environment details while diagnosing them.
- Do not derive the promotion head from the current checkout. The command must
  remain correct when invoked from a feature branch.
- Do not weaken the title workflow to run head code, expand permissions, use an
  unpinned action, or adopt `pull_request_target`.
- Do not assume a bot-created PR's checks are either automatically complete or
  permanently absent. Approval and branch-bypass behavior is GitHub governance,
  not title-validation logic.
- Do not claim the Make target enforces merge commits. Server-side branch rules
  are the only durable enforcement; the target and docs provide a warning.

## Non-Goals And Boundaries

This issue does not merge the promotion PR, push branches, update `main`, cut a
release, edit the version or `CHANGELOG.md`, change Release Please behavior,
replace the automated back-merge, or invoke Scorecard/docs deployment directly.
It does not add an APTL command, package, schema, DTO, controller, service,
repository, exception hierarchy, logger, telemetry signal, secret, PAT,
container, or local persistence. Branch-specific server-side merge-method
enforcement and redesigning bot-trigger authentication are separate governance
changes unless explicitly accepted into scope.
