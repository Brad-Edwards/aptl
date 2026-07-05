# Releasing aptl

aptl publishes to PyPI. Version and changelog are committed files; releasing is a
normal PR; merging it tags + publishes. No bots, deploy keys, or bypasses.

## For every PR (all contributors / agents)

- **Never edit `CHANGELOG.md` directly.** Add a towncrier fragment instead:
  `changelog.d/<issue-or-slug>.<type>.md`, where `<type>` is one of
  `added`, `changed`, `fixed`, `removed`, `deprecated`, `security`. Unique
  filenames mean concurrent PRs never conflict on the changelog.
- **Never hand-edit the version.** It lives only in `src/aptl/__init__.py`
  (`__version__`); `pyproject.toml` reads it via `[tool.hatch.version]`.
- PR titles are conventional and enforced (`<type>: <lowercase subject>`).

## Cutting a release (maintainer)

```bash
python tools/release.py            # computes the next version from the pending
                                   # fragments, writes __version__, builds CHANGELOG.md
git switch -c release/vX.Y.Z
git commit -am "chore: release vX.Y.Z"
gh pr create --base main --title "chore: release vX.Y.Z" --fill
```

Review and merge that PR into `main` (a normal PR — satisfies branch protection).
On merge, `.github/workflows/release.yml`:

1. reads `__version__`; if `vX.Y.Z` isn't tagged yet, proceeds;
2. tags `vX.Y.Z` (a tag, not a commit — no protected-branch push);
3. builds sdist + wheel, generates a CycloneDX SBOM;
4. publishes to PyPI via OIDC trusted publishing;
5. cuts a GitHub Release whose notes are the new `CHANGELOG.md` section.

A normal (non-release) merge leaves `__version__` unchanged, its tag already
exists, and the workflow is a no-op.

## Version rubric (what `tools/release.py` computes)

Pre-1.0 (`major == 0`): any `added` / `changed` / `removed` / `deprecated`
fragment → **minor**; otherwise `fixed` / `security` → **patch**. Once `major >=
1`, a `removed` fragment is a breaking **major** bump.

Override with `python tools/release.py --version X.Y.Z` (used for the first
release, `0.1.0`, which folds the accumulated fragments without a bump).

## One-time setup on PyPI

Register a trusted publisher for the `aptl` project (pypi.org → Account →
Publishing → add pending publisher): owner `Brad-Edwards`, repo `aptl`, workflow
`release.yml`, environment `pypi`. aptl also depends on `aces-sdl`, which must be
on PyPI first.
