# Changelog Fragments

Every PR with a user-visible change drops one small Markdown file in this
directory. The release process (`towncrier build`) collates the fragments
into [`../CHANGELOG.md`](../CHANGELOG.md) and removes the consumed files.

This exists because hand-editing the top of `CHANGELOG.md` in every PR
creates predictable merge conflicts whenever two PRs are open at once.
Fragments live in their own files, so two PRs normally never write to the
same path.

## Add A Fragment

Create one file here per change, named:

```text
<issue>.<type>.md
```

`<issue>` is the GitHub issue or PR number, used to render `(#NNN)` next
to the bullet. If the change has no issue or PR, prefix the slug with `+`
and the suffix is suppressed, for example `+fix-typo.fixed.md`.

`<type>` is one of these Keep a Changelog sections, in this order:

- `security` - vulnerability fixes and hardening
- `added` - new features
- `changed` - changes to existing behavior
- `deprecated` - soon-to-be-removed features
- `removed` - removed features
- `fixed` - bug fixes

The file body is the bullet text. Markdown is allowed. Keep each fragment
to one paragraph; if a change really needs several bullets, split it
across several fragments.

## Example

`288.added.md`:

```markdown
**Adopted `towncrier` for changelog management.** PRs now add fragments
under `changelog.d/` instead of hand-editing `CHANGELOG.md`.
```

renders as:

```markdown
- **Adopted `towncrier` for changelog management.** PRs now add fragments
  under `changelog.d/` instead of hand-editing `CHANGELOG.md`. (#288)
```

## Build The Changelog

Run this at release time:

```sh
uvx towncrier build --version <X.Y.Z> --date $(date -u +%F)
```

This collates `changelog.d/*.md` into a new release block at the top of
`CHANGELOG.md`, just under the `<!-- towncrier release notes start -->`
marker. It also deletes the consumed fragments and stages the changes.

## Preview Without Writing

```sh
uvx towncrier build --draft --version <X.Y.Z>
```

This prints the rendered block to stdout without modifying files.

## Check For A Fragment

```sh
uvx towncrier check --compare-with origin/dev
```

This returns non-zero if the PR has no fragment under `changelog.d/`.
Some PRs, such as pure refactors, CI-only changes, and docs-only changes,
may legitimately have nothing user-visible to say.
