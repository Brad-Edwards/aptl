---
id: DET-001
title: "Detection-as-Code with Sigma Rule Support"
status: DRAFT
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:49:39.006043Z
updated_at: 2026-03-21T07:49:39.006043Z
---

# DET-001: Detection-as-Code with Sigma Rule Support

## Statement

Detection rules shall follow detection-as-code practices. The platform shall support Sigma rules as the canonical detection format, with compilation to platform-native formats (Wazuh XML, Suricata rules) via pySigma or equivalent tooling.

## Rationale

Hand-written XML rules don't benefit from the 3,000+ community Sigma rules. pySigma has a Wazuh backend. Detection-as-code enables version control, review, and automated testing of detection logic.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#430` (DET-001: Detection-as-Code with Sigma Rule Support)
