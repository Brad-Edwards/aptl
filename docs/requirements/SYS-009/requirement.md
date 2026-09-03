---
id: SYS-009
title: "Code Quality and Security Practices"
status: ACTIVE
type: NON_FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:05:43.487932Z
updated_at: 2026-03-20T06:18:11.648456Z
---

# SYS-009: Code Quality and Security Practices

## Statement

The system shall maintain continuous code quality analysis, automated test coverage, and secure credential handling across both Python and TypeScript codebases.

## Rationale

A security training lab that has poor code quality or leaks credentials undermines its own credibility. Continuous quality gates prevent regression and provide confidence in the platform's reliability.

## Traceability

- IMPLEMENTS → CONFIG `eslint.config.js` (Root ESLint flat config: per-function TypeScript complexity gate (issue #286))
- IMPLEMENTS → CONFIG `.pre-commit-config.yaml` (ts-complexity pre-commit hook (TypeScript complexity gate, issue #286))
- DOCUMENTS → ADR `ADR-010` (ADR-010 SonarCloud quality: TypeScript complexity gate section + backlog)
