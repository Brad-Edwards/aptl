---
id: SCN-001
title: "Declarative YAML Scenario Specifications"
status: DEPRECATED
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:12:15.095861Z
updated_at: 2026-05-19T05:11:55.748576Z
---

# SCN-001 — Declarative YAML Scenario Specifications

## Statement

Scenarios shall be defined in YAML files (scenarios/*.yaml) validated by Pydantic models, containing: metadata (id, name, description, version, difficulty, estimated_minutes, tags), mode (red/blue/purple), container requirements, attack steps with technique references, objectives with scoring, hints with point penalties, and expected detections.

## Rationale

Declarative YAML separates scenario content from execution logic.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-009-scenario-engine.md` (ADR-009: Scenario Engine)
- IMPLEMENTS → CODE_FILE `src/aptl/core/scenarios.py` (Scenario definition models)
- IMPLEMENTS → DOCUMENTATION `docs/components/default-defensive-posture.md` (Default defensive posture: scenario mode contract appendix)
- IMPLEMENTS → GITHUB_ISSUE `251` (Issue 251 — document default defensive posture)
- IMPLEMENTS → GITHUB_ISSUE `252` (Issue #252 — references SCN-001's mode field as the future gate for the carve-out)
- IMPLEMENTS → ADR `docs/adrs/adr-014-scenario-description-language.md` (ADR-014 — SCN-001 reconciliation guardrail (codex-added: future scenario-level fields like mode are explicit Pydantic fields, not raw YAML side channels))
