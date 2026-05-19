# Integration Lessons

This directory records integration findings from co-evolving APTL with sibling
research projects — primarily ACES (`autarchy-ai/aces`,
sibling repo at `../aces-sdl`).

It is not a decision log. ADRs continue to record decisions; this directory
records the **post-decision evidence** that emerges when one repo's contracts
meet another repo's reality. Findings here may produce follow-up issues,
amendments to existing ADRs, or new ADRs — but the finding entry stays as the
historical record.

## When To Write An Entry

Write a new entry when:

- A contract surface published by a sibling repo is ambiguous, incomplete,
  or assumes something that doesn't hold for a real backend.
- APTL's adapter has to work around a sibling repo's API shape — either
  because the shape is wrong, or because APTL's existing surface predates
  the contract.
- A fixture corpus or conformance suite passes locally but the real
  integration fails (or vice versa).
- A design decision recorded in an ADR turns out to be wrong, or right but
  for a different reason than the ADR stated.
- A piece of cross-repo coordination cost surprised you — naming, schema
  version handling, dependency pinning, release cadence.

Routine implementation work does NOT need an entry. Don't dilute the
signal.

## Convention

One Markdown file per finding, named `YYYY-MM-DD-<short-slug>.md`. Slug is
kebab-case; pick the noun the finding is about, not a verb.

Each entry's frontmatter:

```markdown
---
date: 2026-05-19
side: APTL | ACES | both
sibling_entry: <link to the matching entry in the sibling repo, if any>
follow_ups:
  - <repo>#<issue> — one-line description
adr_impact:
  - ADR-NNN — amendment / supersede / new ADR
---
```

Body sections (use the ones that apply, omit the rest):

- **Context** — what we were trying to do.
- **What we expected** — the contract surface's apparent promise, the ADR's
  claim, or our assumption going in.
- **What we found** — the actual behavior or shape.
- **Decision** — what we did about it in the current PR. Use one of:
  `fix-in-aptl`, `fix-in-aces`, `cross-repo-coordination`, `accept`,
  `escalate`. Do not use `defer` — record a `follow_ups` issue instead.
- **Why this side** — when fix could have landed on either repo, why we
  chose the one we did.
- **Follow-ups** — issues opened on each side, with cross-references.

## Cross-Repo Symmetry

The sibling repository maintains the same convention at the same path
(`docs/lessons/`). Entries that describe the same finding from each side's
viewpoint should link to each other via the `sibling_entry` frontmatter
field. Do not assume a 1:1 mapping — many findings only need an entry on
one side.

## Why Not An ADR

ADRs answer "what did we decide and why." Lessons answer "what did we
discover when the decision met reality." Mixing the two pollutes the
decision record's signal: future readers can't tell where the
authoritative position ends and the war stories begin.

## Why Not Issue Threads

Issue threads scroll, close, and rot. They live on a single repo with
unstable URLs, are gated by GitHub auth for some readers, and are not part
of the source-tree narrative. Lessons are durable next to the code that
embodies them.
