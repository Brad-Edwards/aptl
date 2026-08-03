---
id: SCN-009
title: "Scenario Prerequisite Validation"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 4
created_at: 2026-03-20T06:12:40.178955Z
updated_at: 2026-03-20T06:18:11.649875Z
---

# SCN-009 — Scenario Prerequisite Validation

## Statement

aptl scenario start shall validate that all required lab profiles (as declared in the scenario YAML) are enabled in aptl.json and their containers are running, before starting a session.

## Rationale

Prerequisite validation catches configuration mismatches before the scenario begins.
