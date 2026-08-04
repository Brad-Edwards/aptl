---
id: INT-005
title: "Sigma Rule Pipeline"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:52:04.691079Z
updated_at: 2026-03-21T07:52:04.691079Z
---

# INT-005: Sigma Rule Pipeline

## Statement

The platform shall provide a Sigma rule pipeline using pySigma to compile Sigma rules into Wazuh XML rules and Suricata signatures, enabling import and use of the 3,000+ community Sigma rules.

## Rationale

pySigma has a Wazuh backend. The 3,000+ community Sigma rules represent years of detection engineering knowledge. A compilation pipeline makes this immediately available without manual rule translation.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#446` (INT-005: Sigma Rule Pipeline)
