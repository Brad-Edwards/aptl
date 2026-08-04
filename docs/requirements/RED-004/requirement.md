---
id: RED-004
title: "Red Team Host Monitoring via Wazuh Agent"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 3
created_at: 2026-03-20T06:11:39.139361Z
updated_at: 2026-03-20T06:18:11.649545Z
---

# RED-004: Red Team Host Monitoring via Wazuh Agent

## Statement

The Kali container shall run a Wazuh agent forwarding activity logs to the SIEM. This enables detection of red team commands for blue team scoring and enables the prime scenario's red team detection rules.

## Rationale

Monitoring the attacker host enables blue team objectives and provides ground truth.
