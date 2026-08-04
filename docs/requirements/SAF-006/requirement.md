---
id: SAF-006
title: "Dangerous Action Approval Workflow"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 3
created_at: 2026-03-21T07:51:09.583305Z
updated_at: 2026-06-28T02:51:27.507320Z
---

# SAF-006: Dangerous Action Approval Workflow

## Statement

The platform shall require explicit operator approval for high-risk agent actions (for example, destructive operations, privilege escalation, data exfiltration) before execution, with configurable policies defining which actions require approval at each autonomy tier.

## Rationale

WITHDRAWN 2026-06-28: per-action operator approval before high-risk agent actions contradicts APTL's autonomous live-fire model in a contained range. The genuine containment boundary (keep the blast inside the range) is already covered by SAF-002 (egress firewall) and NET-005 (zone isolation), both CONSTRAINT/MUST/ACTIVE. The residual connection-model-dependent platform-protection concern is to be captured as new requirements, not by reframing this one. See GitHub issue #482. --- Original rationale: Best practice mandates fresh approval per dangerous action. Combining tiered autonomy (SAF-003) with per-action approval provides granular safety control without blocking routine operations.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#482` (SAF-006: Dangerous Action Approval Workflow)
