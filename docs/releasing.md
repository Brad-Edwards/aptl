# Releasing aptl

Releases are automated with [release-please](https://github.com/googleapis/release-please).
Nobody runs a script, hand-edits the version, or edits `CHANGELOG.md`.

## Per PR (all contributors / agents)

- **Squash-merge** PRs so the PR title becomes the commit on the branch.
- The PR title must be a **Conventional Commit** (`<type>: <lowercase subject>`).
  Bump rules: `feat:` → minor, `fix:` / `perf:` → patch, `feat!:` or a
  `BREAKING CHANGE:` footer → major (demoted to minor while `0.x`). Other types
  (`docs`, `chore`, `refactor`, `test`, `ci`, `build`) → no release.
- Use one Conventional Commit type and scope only; compound titles such as
  `fix(...) + docs:` are not parseable by release-please.
- **Do not** edit `CHANGELOG.md` or the version; release-please owns both.
  Because feature PRs never touch `CHANGELOG.md`, concurrent PRs never conflict
  on it.

## Promoting `dev` to `main`

Feature PRs land on `dev`. Nothing releases until `dev` is promoted to `main`.

Open the promotion PR with:

```bash
make devmain
```

That creates a `dev` → `main` PR titled `chore(main): promote dev`. The title is
fixed rather than free-form because it is unambiguous and `chore` is a
no-release type, so the promotion never computes a version bump of its own.

GitHub's web and API flows can instead generate the branch title `Dev`. The
PR-title guard accepts that fallback only when the event identifies the exact
same-repository `dev` → `main` branch pair. Forks, differently named heads,
other base branches, and arbitrary titles remain subject to the normal
Conventional Commit policy.

**Merge the promotion with a merge commit. Do not squash it.** This is the one
place in the workflow where squashing is wrong. release-please computes the
version and `CHANGELOG.md` from the Conventional Commit subjects on `main`;
squashing collapses every feature commit in the batch into a single subject, so
the release loses its changelog entries and can compute the wrong bump. A merge
commit preserves each subject underneath.

The merge commit's own subject (`Merge pull request #N from ...`) is not a
Conventional Commit and does not need to be—release-please reads the feature
commits it carries, not the merge subject.

Promotion also refreshes repository posture: `.github/workflows/scorecard.yml`
runs only on pushes to `main`, so the published OpenSSF Scorecard result and the
README badge do not update until a promotion lands.

## How a release happens

1. On merges to `main`, release-please keeps a **release PR** open
   (`chore(main): release X.Y.Z`) with the computed version bump in
   `pyproject.toml` and the generated `CHANGELOG.md` section.
2. **Merge that release PR.** It's opened by `GITHUB_TOKEN`. Workflow runs
   triggered that way are restricted: depending on the repository's Actions
   settings they may not start at all, or may sit awaiting approval. Either way
   do not expect the required checks to go green on their own—merge it as an
   admin, or wire a PAT if you want checks genuinely enforced on the release PR.
3. Merging tags `vX.Y.Z` and cuts the GitHub Release; the `publish` job then
   builds the sdist + wheel, generates an SBOM, and publishes to PyPI via OIDC.
4. A `main`→`dev` **back-merge PR** is then opened automatically (main now has
   the version bump + `CHANGELOG.md`), titled `chore: back-merge <tag> into dev`.
   **Admin-merge it** (one click) to keep `dev` current—like the release PR it
   is bot-opened, so its required checks should not be relied on to run.

## Baseline

The released baseline is `3.0.10` (the last git tag `v3.0.10`), recorded in
`.release-please-manifest.json` and `pyproject.toml`. release-please computes the
next version from that baseline plus the Conventional Commits merged since, so a
`feat!:` change cuts `4.0.0`, and no version or `CHANGELOG.md` is ever
hand-edited. There is no manual bootstrap step.

## PyPI trusted publisher (one-time)

pypi.org → Account → Publishing → add pending publisher: project `aptl-labs`, owner
`Brad-Edwards`, repo `aptl`, workflow `release-please.yml`, environment `pypi`.
`raes` must be on PyPI first (aptl depends on it). The distribution is named
`aptl-labs` because `aptl` is reserved on PyPI; the import package and CLI stay `aptl`.
