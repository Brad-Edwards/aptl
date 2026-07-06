# APTL plan rules

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
  every MCP server consumes it. After changing common, every dependent
  MCP must rebuild and its tests must pass before the change is
  considered complete.
- Plans that change `docker-compose.yml`, container Dockerfiles, or
  `config/` files MUST validate that a clean `aptl lab stop -v && aptl
  lab start` produces a healthy lab on a fresh machine — the lab is the
  primary product, not the codebase.
- Plans MUST NOT edit `CHANGELOG.md` or the version. Releases are automated by
  release-please from Conventional Commit PR titles: `feat:` (minor),
  `fix:`/`perf:` (patch), `feat!:` or a `BREAKING CHANGE:` footer (major);
  `docs`/`chore`/`refactor`/`test`/`ci`/`build` do not release. The PR title is
  the changelog entry, so make it a clear Conventional Commit. See
  `docs/releasing.md`.
