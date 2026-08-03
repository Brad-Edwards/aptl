---
id: SEC-004
title: "TLS Between Wazuh Components"
status: ACTIVE
type: NON_FUNCTIONAL
priority: SHOULD
wave: 1
created_at: 2026-03-20T06:10:10.173444Z
updated_at: 2026-03-20T06:18:11.648972Z
---

# SEC-004 — TLS Between Wazuh Components

## Statement

All Wazuh inter-component communication (Manager to Indexer, Dashboard to Indexer, Dashboard to Manager API) shall use TLS with generated certificates. The MCP common library's HTTPClient shall use per-request https.Agent with rejectUnauthorized: false for self-signed lab certificates, not process-global NODE_TLS_REJECT_UNAUTHORIZED.

## Rationale

Per-request SSL handling prevents the security anti-pattern of globally disabling certificate verification.
