# ADR-038: Documentation Style Lint and Published Docs Site

## Status

accepted

## Date

2026-06-11

## Context

Issue #407 (requirement DOC-001) found the documentation corpus in poor
shape: `mkdocs.yml` referenced 12 pages that did not exist, listed only
12 of 38 ADRs, and omitted entire sections (`sdl/`, `aces/`, `testing/`,
most of `components/`); no prose linting existed anywhere in the repo;
and the docs were not published, despite a fully configured
mkdocs-material theme. Prose quality drifted unchecked because nothing
gated it, and nav drift went unnoticed because nothing built the site.

An upstream workflow platform already runs a proven apparatus for this:
a pinned, checksum-verified Vale install script, a pre-commit wrapper
hook, the Google style package at error level, and a small house-style
overlay. Porting it is cheaper and better-tested than inventing a new
one.

## Decision

Adopt Vale as the prose linter and publish the docs site to GitHub
Pages, gated by a strict mkdocs build.

- **Vale, Google style, error level.** `.vale.ini` applies the Google
  package plus an `AptlProject` overlay (tracked under
  `.vale/styles/AptlProject/`) to all markdown, with
  `MinAlertLevel = error`. `tools/install-vale.sh` installs a pinned,
  SHA-256-verified Vale binary into the gitignored `.tools/` directory;
  `tools/vale-lint-hook.sh` is the pre-commit entry point and
  `tools/vale-lint-all.sh` lints the full corpus in CI.
- **Reasoned exclusions, not blanket ones.** Generated artifacts
  (`CHANGELOG.md`, `changelog.d/`), agent-facing contracts (`.claude/`,
  `.gc/`, `.github/`, `AGENTS.md`, `CLAUDE.md`), ACES inventory
  evidence bundles, and dated point-in-time records (`docs/history/`,
  `docs/known-issues/`, smoke-test results) carry empty
  `BasedOnStyles` blocks in `.vale.ini`: the record value of those
  files outweighs style conformance, and rewriting history to satisfy
  a linter is worse than not linting it.
- **`Google.Units` is disabled.** Lab docs quote literal config values
  (`512MB` memory limits, `300s` timeouts). Inserting a space between
  number and unit would make prose diverge from the strings that
  appear in compose files and CLI output.
- **Strict mkdocs build in CI.** The `docs` job in `checks.yml` runs
  `mkdocs build --strict`, so a nav entry pointing at a missing page or
  a broken internal link fails the build instead of rotting silently.
- **GitHub Pages deploy on `main`.** A dedicated workflow builds the
  site and deploys it via `actions/deploy-pages` on pushes to `main`.
  The `mike` version provider was dropped from `mkdocs.yml`: no
  versioned-docs workflow exists, and carrying the config without the
  apparatus misleads.

## Consequences

- Markdown touched by a commit must pass Google style at error level
  before it lands; CI re-checks the whole corpus, so drift cannot
  re-enter through excluded paths or merge skew.
- The published site exposes nav rot immediately: a page that exists
  on disk but not in `nav` is visible in the strict build log, and a
  removed page fails the build.
- Contributors get one new local dependency, installed automatically
  and verified by checksum on first commit that touches markdown.
- The Google style is a US-English, developer-docs voice. Where it
  conflicts with deliberate house usage the fix is a tracked rule in
  `AptlProject/`, not a per-file waiver.

## Non-Goals

- Spell-checking and warning/suggestion-level style advice. The gate
  is errors only; raising `MinAlertLevel` later is a one-line change.
- Linting prose inside code comments, SDL YAML descriptions, or web UI
  strings. The gate covers markdown only.
- Versioned documentation. If a release-versioned site is wanted
  later, reintroduce `mike` together with the workflow that drives it.

## References

- Issue [#407](https://github.com/Brad-Edwards/aptl/issues/407), requirement DOC-001
- The upstream workflow platform's ADR-054 (Vale gate) and ADR-055 (style exclusions), the ported pattern
- [ADR-026](adr-026-advisory-ci-vulnerability-scanning.md): the checks.yml advisory/blocking job split this docs job slots into
