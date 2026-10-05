# LilRAE plan rules

Mandatory constraints the `/implement` skill applies during plan phase.

- Plans that add or change Python code MUST include corresponding pytest
  tests in `tests/`. Use `pytest -m fuzz` for property-based tests
  (the default test run skips them per `pyproject.toml`).
- Plans that add or change MCP TypeScript servers (anything under `mcp/`)
  MUST include corresponding vitest tests in that server's `tests/`
  directory.
- Plans that add or change web frontend code MUST include corresponding
  vitest tests in `web/tests/`.
- Plans that touch `mcp/aptl-mcp-common` MUST account for the fact that
  every MCP server consumes it. Run only targeted common and consumer tests
  locally; CI/CD rebuilds and tests every dependent MCP before the change is
  considered complete.
- Plans that change any Compose asset (`docker-compose*.yml`), container
  Dockerfiles, or `config/` files MUST include focused local contract tests.
  CI/CD owns the clean `aptl lab stop -v && aptl lab start` validation on a
  fresh machine — the lab is the primary product, not the codebase.
- Local verification MUST remain change-scoped: targeted pytest or Vitest
  paths plus `pre-commit run` on staged files. Bare/full suites,
  `pre-commit run --all-files`, whole-tree prose checks, dependency checks, and
  coverage runs are CI/CD-only.
- Plans MUST NOT edit `CHANGELOG.md` or the version. Releases are automated by
  release-please from Conventional Commit PR titles: `feat:` (minor),
  `fix:`/`perf:` (patch), `feat!:` or a `BREAKING CHANGE:` footer (major);
  `docs`/`chore`/`refactor`/`test`/`ci`/`build` do not release. The PR title is
  the changelog entry, so make it a clear Conventional Commit. See
  `docs/releasing.md`.
- New code MUST use `lilrae` naming: a new module, package, service,
  environment variable (`LILRAE_`), resource name, or configuration file is
  named for LilRAE, not APTL. Code that extends an existing interface MUST keep
  that interface's current identifiers (for example the `aptl` import root,
  `aptl` CLI, `aptl.*` entry-point groups, existing config fields, `APTL_*`
  variables, and runtime resource names); add no alias, shim, or parallel
  `lilrae` spelling. Renaming an existing identifier needs its own
  compatibility decision. See
  [ADR-062](../docs/adrs/adr-062-lilrae-name-and-naming-convention.md).
