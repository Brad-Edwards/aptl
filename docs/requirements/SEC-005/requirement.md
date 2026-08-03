---
id: SEC-005
title: ".env Credential Isolation from Version Control"
status: ACTIVE
type: CONSTRAINT
priority: MUST
wave: 1
created_at: 2026-03-20T06:10:12.887986Z
updated_at: 2026-03-20T06:18:11.648994Z
---

# SEC-005 — .env Credential Isolation from Version Control

## Statement

Runtime credentials shall be stored exclusively in a .env file that is listed in .gitignore. docker-compose.yml shall reference credentials only through variable substitution. No credentials shall be committed to version control.

## Rationale

Credential leakage to version control is a common and severe security mistake.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/utils/placeholders.py` (.env.example placeholder marker registry)
- IMPLEMENTS → CODE_FILE `src/aptl/core/env.py` (.env loader + sensitive-var placeholder guard)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Lab-start placeholder-secret guard)
- TESTS → TEST `tests/test_env.py` (Placeholder-guard tests)
