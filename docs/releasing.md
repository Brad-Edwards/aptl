# Releasing aptl

Releases are automated with [release-please](https://github.com/googleapis/release-please).
Nobody runs a script, hand-edits the version, or edits `CHANGELOG.md`.

## Per PR (all contributors / agents)

- **Squash-merge** PRs so the PR title becomes the commit on the branch.
- The PR title must be a **Conventional Commit** (`<type>: <lowercase subject>`).
  Bump rules: `feat:` → minor, `fix:` / `perf:` → patch, `feat!:` or a
  `BREAKING CHANGE:` footer → major (demoted to minor while `0.x`). Other types
  (`docs`, `chore`, `refactor`, `test`, `ci`, `build`) → no release.
- **Do not** edit `CHANGELOG.md` or the version; release-please owns both.
  Because feature PRs never touch `CHANGELOG.md`, concurrent PRs never conflict
  on it.

## How a release happens

1. On merges to `main`, release-please keeps a **release PR** open
   (`chore(main): release X.Y.Z`) with the computed version bump in
   `pyproject.toml` and the generated `CHANGELOG.md` section.
2. **Merge that release PR.** It's opened by `GITHUB_TOKEN`, so the required CI
   checks don't auto-run on it, so merge it as an admin (or wire a PAT if you want
   checks enforced on the release PR).
3. Merging tags `vX.Y.Z` and cuts the GitHub Release; the `publish` job then
   builds the sdist + wheel, generates an SBOM, and publishes to PyPI via OIDC.
4. A `main`→`dev` **back-merge PR** is then opened automatically (main now has
   the version bump + `CHANGELOG.md`). **Admin-merge it** (one click; dev's
   required checks don't run on a bot-opened PR) to keep `dev` current.

## First release (one-time bootstrap)

The current baseline is `0.1.0` and its `CHANGELOG.md` section already exists.
release-please won't re-cut `0.1.0`, so publish it once manually:
**Actions → Release → Run workflow** (`workflow_dispatch`). That builds and
publishes the current committed version. Every release after that is
release-please-driven.

## PyPI trusted publisher (one-time)

pypi.org → Account → Publishing → add pending publisher: project `aptl`, owner
`Brad-Edwards`, repo `aptl`, workflow `release.yml`, environment `pypi`.
`aces-sdl` must be on PyPI first (aptl depends on it).
