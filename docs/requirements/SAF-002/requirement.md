---
id: SAF-002
title: "Network Egress Firewall on Docker Networks"
status: ACTIVE
type: CONSTRAINT
priority: MUST
wave: 1
created_at: 2026-03-21T07:50:53.921160Z
updated_at: 2026-03-22T02:35:27.417368Z
---

# SAF-002: Network Egress Firewall on Docker Networks

## Statement

Lab Docker networks shall enforce egress controls preventing containers from reaching the internet. At minimum, networks carrying attack traffic shall use Docker's internal: true flag or equivalent iptables rules to block outbound connectivity.

## Rationale

All 4 Docker networks currently use driver: bridge without internal: true, meaning lab containers can reach the internet. An autonomous agent could inadvertently scan or attack external targets.

## Traceability

- TESTS → TEST `tests/test_consistency.py` (TestNetworkEgressControls consistency tests)
- DOCUMENTS → GITHUB_ISSUE `231` (SAF-002: Network Egress Firewall on Docker Networks)
- IMPLEMENTS → CODE_FILE `docker-compose.yml` (Docker Compose network definitions with internal: true)
- DOCUMENTS → DOCUMENTATION `docs/architecture/networking.md` (Network architecture egress controls documentation)
