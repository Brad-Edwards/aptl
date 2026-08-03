---
id: DOC-001
title: "Accurate, Style-Linted, Published Documentation"
status: ACTIVE
type: NON_FUNCTIONAL
priority: SHOULD
wave: 1
created_at: 2026-06-11T15:09:12.689452Z
updated_at: 2026-06-11T15:09:30.834369Z
---

# DOC-001 — Accurate, Style-Linted, Published Documentation

## Statement

The project shall maintain documentation that is verified accurate against the current code and configuration, readable and accessible (consistent structure, working cross-links, coherent navigation), enforced by an automated prose style-lint gate in pre-commit and CI, and published as a public docs site on GitHub Pages that rebuilds automatically from the main branch with the mkdocs navigation reconciled to the actual docs tree (strict build passes).

## Rationale

APTL's documentation has drifted: the mkdocs nav references 12 pages that do not exist, lists only 12 of 38 ADRs, and omits entire sections (SDL, ACES, testing, most components); no prose linting exists and the docs are not published anywhere. A research lab whose docs are stale or unreachable undermines adoption and reproducibility. Ground-Control's Vale apparatus provides a proven pattern to port.

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `407` (Full documentation overhaul: accuracy, readability, Vale lint gate, mkdocs nav repair, and GitHub Pages)
- DOCUMENTS → ADR `ADR-038` (Documentation Style Lint and Published Docs Site)
- IMPLEMENTS → CONFIG `.vale.ini` (Vale prose-lint configuration (Google + AptlProject styles))
- IMPLEMENTS → CONFIG `mkdocs.yml` (mkdocs site configuration (nav reconciled, strict-buildable))
- IMPLEMENTS → CONFIG `.github/workflows/docs-deploy.yml` (GitHub Pages docs deploy workflow)
- IMPLEMENTS → PULL_REQUEST `408` (Docs overhaul: Vale lint gate, mkdocs nav repair, GitHub Pages, accuracy sweep)
- IMPLEMENTS → PULL_REQUEST `410` (Guard docs-deploy jobs to main ref only)
