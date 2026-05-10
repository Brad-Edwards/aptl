# ADR-010: SonarCloud for Continuous Code Quality

## Status

accepted

## Date

2026-03-07

## Context

APTL had no automated code quality analysis. Code quality was assessed through manual review only — first during development, then formally in the team review documented in `notes/team-review-synthesis.md`. That review found 30 issues (17 major, 13 minor), including `any`-typed MCP args, duplicated code, dead config fields, and a process-global SSL disable.

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
- **CI pipeline complexity**: The workflow must install Python, Node.js, run two test suites, and then scan — adding ~3-5 minutes to every CI run.

### Risks

- SonarCloud free tier limits may be reached as the codebase grows (currently well within limits for open-source projects)
- Coverage thresholds are not yet enforced as quality gates — currently informational only

## Update (2026-05-10): SonarCloud gate stays advisory; a hard in-repo complexity gate is added

The SonarCloud analysis now lives in `.github/workflows/checks.yml` (the
former `sonarcloud.yml` was folded in), and the quality-gate job is run
**advisory** (`continue-on-error`, no `-Dsonar.qualitygate.wait`): the
"Sonar way" gate's *Coverage on New Code ≥ 80%* condition would otherwise
block infra-only commits (Dockerfiles, compose, workflows, scripts) that add
no covered code. The scan still runs on every PR/push and the dashboard
reflects current state; SonarCloud's PR analysis is also new-code-scoped, so
it only surfaces issues on the lines a PR changes — pre-existing complexity
debt in a lightly-touched file is invisible to it.

To keep god-methods / non-modular code out of the tree without the coverage
trap and without the new-code-only blind spot, a dedicated, **hard**,
repo-wide per-function complexity gate runs in pre-commit and CI: `ruff
check src/` with **only `C901` enabled** (`[tool.ruff.lint] select =
["C901"]`) and `[tool.ruff.lint.mccabe] max-complexity = 15` — matching
SonarCloud's default cognitive-complexity threshold (cyclomatic complexity is
a fine proxy for "this method does too much"). This is the only `ruff` rule
turned on; it is a complexity guard, not a style linter — widen the rule set
deliberately if/when the team wants more from `ruff`.

### Complexity backlog (carved out with `# noqa: C901`)

These functions exceed the threshold today and are exempted **at the site**
(`# noqa: C901` on the `def` line) until split. They are the standing
refactor backlog — do not add to it; peel them off one PR at a time and
ratchet `max-complexity` down as the list shrinks:

| Function | File | CC |
| --- | --- | --- |
| `compile_runtime_model` | `src/aptl/core/runtime/compiler.py` | 45 |
| `_verify_objectives` | `src/aptl/core/sdl/validator.py` | 43 |
| `_verify_workflows` | `src/aptl/core/sdl/validator.py` | 37 |
| `_validate_manifest` | `src/aptl/core/runtime/planner.py` | 31 |
| `_verify_infrastructure` | `src/aptl/core/sdl/validator.py` | 31 |
| `_verify_agents` | `src/aptl/core/sdl/validator.py` | 25 |
| `_collect_resources` | `src/aptl/core/runtime/planner.py` | 18 |
| `_expand_shorthands` | `src/aptl/core/sdl/parser.py` | 17 |

(SonarCloud separately flags a different set under its *cognitive* metric —
e.g. deeply-nested functions in `snapshot.py` / `collectors.py` / `env.py` /
`detection.py` / `cli/runs.py`; the two checks are complementary and both
worth driving to zero.)
