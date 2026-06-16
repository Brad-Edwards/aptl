# ADR-010: SonarCloud for Continuous Code Quality

## Status

accepted

## Date

2026-03-07

## Context

APTL had no automated code quality analysis. Code quality was assessed through manual review only—first during development, then formally in the team review documented in `notes/team-review-synthesis.md`. That review found 30 issues (17 major, 13 minor), including `any`-typed MCP args, duplicated code, dead config fields, and a process-global SSL disable.

As the codebase grew to include both Python (`src/aptl/`, 587+ tests) and TypeScript (`mcp/`, vitest tests), a continuous quality gate was needed to catch regressions before they accumulate.

## Decision

Integrate SonarCloud via GitHub Actions for continuous code quality analysis across both language stacks.

### Configuration

**`sonar-project.properties`**:
- Sources: `src` (Python) and `mcp` (TypeScript)
- Tests: `tests` (Python) and `mcp/aptl-mcp-common/tests` (TypeScript)
- Exclusions: `node_modules`, `__pycache__`, `dist`, `.venv`, `build`, `containers`, and `mcp/**/tests/**` (to prevent test files from being double-indexed as both source and test)

**Coverage pipeline** (`.github/workflows/sonarcloud.yml`):
1. Python: `pytest --cov` generates `coverage.xml`
2. TypeScript: `vitest --coverage` in `mcp/aptl-mcp-common/` generates `lcov.info`
3. SonarCloud scan reads both coverage reports

### Key Implementation Details

- **Test file separation**: MCP test files under `mcp/**/tests/**` are added to `sonar.exclusions` (excluded from source analysis) while simultaneously listed in `sonar.tests` (recognized as test sources). Without this, SonarCloud reported "can't be indexed twice" errors (v4.6.8).
- **Coverage bootstrapping**: The initial CI workflow ran SonarCloud without running tests first, resulting in 0% coverage. Fixed by adding pytest and vitest steps before the scan (v4.5.0, v4.6.8).
- **Scanner migration**: Migrated from deprecated `SonarSource/sonarcloud-github-action` to `SonarSource/sonarqube-scan-action@v7` (v4.7.0).
- **CI action versions**: Upgraded to Node.js 24-compatible versions (`actions/checkout@v6`, `actions/setup-python@v6`, `actions/setup-node@v6`) in v4.7.0.

## Consequences

### Positive

- **Continuous quality gate**: Every PR and push to main gets automated quality analysis
- **Dual-language coverage**: Both Python and TypeScript codebases have measured test coverage
- **Historical tracking**: SonarCloud maintains quality metrics over time, showing trends

### Negative

- **External dependency**: SonarCloud is a third-party service. Outages block quality gate checks.
- **CI pipeline complexity**: The workflow must install Python, Node.js, run two test suites, and then scan—adding ~3-5 minutes to every CI run.

### Risks

- SonarCloud free tier limits may be reached as the codebase grows (currently well within limits for open-source projects)
- Coverage thresholds are not yet enforced as quality gates—currently informational only

## Update (2026-05-10): SonarCloud gate stays advisory; a hard in-repo complexity gate is added

The SonarCloud analysis now lives in `.github/workflows/checks.yml` (the
former `sonarcloud.yml` was folded in), and the quality-gate job is run
**advisory** (`continue-on-error`, no `-Dsonar.qualitygate.wait`): the
"Sonar way" gate's *Coverage on New Code ≥ 80%* condition would otherwise
block infra-only commits (Dockerfiles, compose, workflows, scripts) that add
no covered code. The scan still runs on every PR/push and the dashboard
reflects current state; SonarCloud's PR analysis is also new-code-scoped, so
it only surfaces issues on the lines a PR changes—pre-existing complexity
debt in a lightly touched file is invisible to it.

To keep god-methods / non-modular code out of the tree without the coverage
trap and without the new-code-only blind spot, a dedicated, **hard**,
repo-wide per-function complexity gate runs in pre-commit and CI: `ruff
check src/` with **only `C901` enabled** (`[tool.ruff.lint] select =
["C901"]`) and `[tool.ruff.lint.mccabe] max-complexity = 15`—matching
SonarCloud's default cognitive-complexity threshold (cyclomatic complexity is
a fine proxy for "this method does too much"). This is the only `ruff` rule
turned on; it is a complexity guard, not a style linter; widen the rule set
deliberately if/when the team wants more from `ruff`.

### TypeScript complexity extension guardrails

Issue #286 extends the same hard gate to the TypeScript surfaces. Treat that
as the same cross-cutting quality policy as `ruff-complexity`, not as a
package-local lint cleanup. The TypeScript gate must stay narrow: per-function
complexity only, threshold 15, no formatting/import/style/recommended-rule
overhaul bundled with it.

The canonical enforcement point is the required `Pre-commit hooks` check in
`.github/workflows/checks.yml`, matching the Python gate. If implementation
chooses a separate required CI job instead, keep the pre-commit hook for local
parity. In either form, the gate must run before slower vitest hooks and must
not be skipped by the existing CI `SKIP` list.

Scope is `mcp/*/src/**/*.ts` and `web/src/**/*.{ts,svelte}`. Generated output,
tests, `node_modules`, package `build/` directories, and `web/.svelte-kit/`
remain out of scope. `web/src` contains Svelte components, so a TS-only glob
would miss functions in `<script lang="ts">` blocks and does not satisfy the
contract.

Keep one source of truth for the threshold, target globs, and legacy
exemptions. Reuse the existing flat ESLint/TypeScript-parser pattern if ESLint
is selected, but do not copy the full `mcp-red` / `mcp-reverse` style lint
rules into every package. Biome is acceptable only if it covers the same
`mcp` and Svelte inputs and can express explicit legacy exemptions. Existing
offenders should be carved out with the narrowest tool-supported exemption and
listed in this ADR's backlog with measured scores; new code should not be
added to exempted files.

### TypeScript complexity gate (realized)

Issue #286 ships the gate as ESLint's core `complexity` rule at `["error", {
max: 15 }]`, the same cyclomatic metric as `ruff` `C901`. The single source of
truth is the root `eslint.config.js`: it holds the threshold, the target globs
(`mcp/*/src/**/*.ts` and `web/src/**/*.{ts,svelte}`), and the out-of-scope
`ignores` (`build/`, `dist/`, `node_modules/`, `web/.svelte-kit/`, tests). It
currently carries no per-file exemptions (see the cleared backlog below). Only
the `complexity` rule is enabled (the
config loads the TypeScript and Svelte parsers but none of their rule plugins),
so it is a complexity guard, not a style linter, and it does not cascade into
the per-package `mcp-red` / `mcp-reverse` configs. Svelte components are
first-class: functions inside `<script lang="ts">` are parsed by
`svelte-eslint-parser` and gated like any `.ts` function.

Enforcement is the `ts-complexity` hook in `.pre-commit-config.yaml`, a
`language: node` hook with pinned `additional_dependencies`, self-contained
like `ruff-complexity`'s pinned `ruff`. It runs immediately after
`ruff-complexity`, before the slower vitest hooks, and is **not** in the CI
`SKIP` list, so it gates in the required `Pre-commit hooks` job and locally from
the same config (no separate CI job and no branch-protection change). The config
is CommonJS so `require()` resolves the pinned parsers through the `NODE_PATH`
that pre-commit's node environment exports; `noInlineConfig` keeps the gate
central and tamper-resistant (a function cannot be exempted with an inline `//
eslint-disable`), and the hook passes `--quiet` so the resulting "directive has
no effect" meta-warnings stay out of the output without hiding a real error.

### TypeScript complexity backlog (cleared)

Empty. Issue #286 added the gate and, in the same change, split the three
functions that were initially over threshold into helpers, so `eslint.config.js`
carries no `complexity: 'off'` exemptions and every function under the scoped
globs is gated at 15. The historical offenders (all CC 18) were `harvestSession`
(`mcp/aptl-mcp-common/src/captures.ts`), `predefined_query`
(`mcp/aptl-mcp-common/src/tools/api-handlers.ts`), and `buildBlockSequence`
(`web/src/lib/workbench.ts`). If a future change must temporarily exempt a file,
add a whole-file `complexity: 'off'` override (never a per-function inline
`// eslint-disable`, which edits the function and drags its pre-existing
complexity into SonarCloud's new-code analysis) and record the offender here
with its measured score.

### Python complexity backlog (cleared)

Empty. Issue #286 split all eight functions that were over threshold into
helpers, so `pyproject.toml` carries no `[tool.ruff.lint.per-file-ignores]`
entries and every function under `src/` is gated at max-complexity 15. The
historical offenders (CC = ruff's McCabe cyclomatic complexity) were:

| Function | File | CC (before) |
| --- | --- | --- |
| `compile_runtime_model` | `src/aptl/core/runtime/compiler.py` | 45 |
| `_verify_objectives` | `src/aptl/core/sdl/validator.py` | 43 |
| `_verify_workflows` | `src/aptl/core/sdl/validator.py` | 37 |
| `_validate_manifest` | `src/aptl/core/runtime/planner.py` | 31 |
| `_verify_infrastructure` | `src/aptl/core/sdl/validator.py` | 31 |
| `_verify_agents` | `src/aptl/core/sdl/validator.py` | 25 |
| `_collect_resources` | `src/aptl/core/runtime/planner.py` | 18 |
| `_expand_shorthands` | `src/aptl/core/sdl/parser.py` | 17 |

If a future change must temporarily exempt a file, re-add the per-file-ignore
table (whole-file, never a per-`def` `# noqa: C901`) and record the offender
here with its measured score.

(SonarCloud's *cognitive*-complexity rule flags a wider, partly different set—
many more functions in `validator.py` plus deeply nested ones in `snapshot.py`
/ `collectors.py` / `env.py` / `detection.py` / `cli/runs.py`, and a CC-66
function in `lab.py` on the older `main` analysis; the two metrics are
complementary and both worth driving to zero.)

Known wart: `src/aptl/core/lab.py:63` has a malformed `# noqa: delayed import
for mocking` (it predates this gate)—`ruff check` prints a one-line warning
for it but still passes. Left as-is here because fixing it touches `lab.py`,
which would drag `lab.py`'s pre-existing SonarCloud issues into this
config-only PR; fix it to `# noqa: PLC0415` the next time `lab.py` is edited.
