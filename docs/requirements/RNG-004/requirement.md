---
id: RNG-004
title: "Multi-Domain AD Forest Topologies"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 4
created_at: 2026-03-21T07:50:20.970774Z
updated_at: 2026-03-21T07:50:20.970774Z
---

# RNG-004: Multi-Domain AD Forest Topologies

## Statement

The lab shall support multi-domain Active Directory forest topologies with trust relationships, enabling scenarios that exercise cross-domain attacks (golden ticket, trust abuse, SID history injection) found in real enterprise environments.

## Rationale

ENT-002 provides a single domain (TECHVAULT.LOCAL). Real enterprises use forests with multiple domains and trusts. Cross-domain attacks are a significant portion of modern threat activity.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#497` (RNG-004: Multi-Domain AD Forest Topologies)
