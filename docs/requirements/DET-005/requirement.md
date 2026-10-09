---
id: DET-005
title: "Cross-Source Detection Correlation"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 3
created_at: 2026-03-21T07:49:55.662255Z
updated_at: 2026-10-09T00:00:00.000000Z
---

# DET-005: Cross-Source Detection Correlation

## Statement

The platform shall correlate detections across multiple sources (for example, Wazuh host-based alert + Suricata network alert) within configurable time windows to identify multi-signal attack patterns that no single source would detect.

## Rationale

WITHDRAWN 2026-10-09: The issue closed as not planned on 2026-07-27 without a closing comment. See GitHub issue #470. --- Original rationale: SOC-006 describes end-to-end workflow integration but not automated cross-source temporal correlation. Real SOC analysts correlate across sources; the platform should automate and score this.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#470` (DET-005: Cross-Source Detection Correlation)
