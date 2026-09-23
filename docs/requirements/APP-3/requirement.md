---
id: APP-3
title: "Signed disposable appliance release envelope"
status: ACTIVE
type: NON_FUNCTIONAL
priority: MUST
wave: 6
created_at: 2026-07-26T01:55:57.080310Z
updated_at: 2026-07-26T04:44:22.303558Z
---

# APP-3: Signed disposable appliance release envelope

## Statement

APTL shall assemble and verify a signed, versioned appliance release envelope that binds an immutable golden guest disk to the exact APTL source revision and version, staged participant profile and asset-lock identities, accepted qualification evidence, appliance boundary policy and helper-image digests, supported delivery adapters, and explicit host prerequisites; release verification shall fail closed on unsafe references, unknown fields, duplicate artifacts, digest or signature mismatch, missing offline inputs, golden-state contamination, insufficient multi-machine qualification, or an attempted in-place upgrade.

## Rationale

For current VM-only seats, ADR-060 defines the signed containment policy.
Issue #1162 replaces the bespoke release transport with the owner-approved
GHCR/Cosign delivery in ADR-060. Traceability below names the replacement
artifacts; ACTIVE status does not assert complete multi-machine qualification.
APP-1 internal-zone implementation is deferred to #1127; the release must name
its actual containment contract and must not claim internal-isolation evidence.

Issue #823 supplies the release artifact consumed by the host launcher in issue #824 and the hosted per-seat adapter in issue #825. APP-1 remains the boundary-enforcement authority and APP-2 remains the bounded participant-profile authority; this requirement binds those existing contracts into one immutable release unit without duplicating their schemas.

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `1022` (VM-only seat delivery and qualification)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/policy.py` (Explicit signed VM-only containment policy)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/seat/lifecycle.py` (Generation-bound VM seat lifecycle and admission)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/seat/prereqs.py` (Host capacity and runtime resource admission)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/access_service.py` (Authenticated seat-scoped host access)
- IMPLEMENTS → CONFIG `.github/workflows/release-please.yml` (Package publication independent of image cuts)
- TESTS → TEST `tests/test_appliance_vm_containment.py` (Containment distinction and retained identity/host checks)
- TESTS → TEST `tests/test_appliance_seat_lifecycle.py` (VM start, readiness, recovery, and revocation)
- TESTS → TEST `tests/test_appliance_seat_prereqs.py` (Capacity and free-space admission boundaries)
- TESTS → TEST `tests/test_appliance_seat_portability.py` (Portable CLI imports and fail-closed POSIX locking)
- TESTS → TEST `tests/test_mcp_protocol.py` (Bounded MCP teardown proof during qualification)
- TESTS → TEST `tests/test_appliance_release_workflow.py` (Release workflow permissions and ordering)
- DOCUMENTS → DOCUMENTATION `docs/adrs/adr-060-vm-only-seat-containment.md` (Owner-approved containment scope)
- DOCUMENTS → DOCUMENTATION `docs/reference/appliance-seat-launcher.md` (Operator security boundary and residual risk)

- IMPLEMENTS → GITHUB_ISSUE `823` (Issue 823: signed disposable appliance release envelope)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Lab appliance lifecycle integration)
- IMPLEMENTS → CODE_FILE `appliance/guest/provision-offline.sh` (Offline appliance guest provisioning)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/input_images.py` (Required OCI configuration and layer identities)
- TESTS → TEST `tests/test_mcp_appliance_admission.py` (Signed launch and fresh boundary binding admission)

- IMPLEMENTS → CODE_FILE `src/aptl/appliance/seat/image.py` (Immutable OCI disk/config resolution)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/seat/image_trust.py` (Cosign publisher authentication and offline admission receipts)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/seat/retained_image.py` (Per-generation image/config/trust retention for offline restart)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/seat/image_update.py` (Confirmed stopped-seat replacement)
- IMPLEMENTS → CODE_FILE `scripts/appliance/build-seat-image.sh` (Local offline guest assembly and sanitization)
- IMPLEMENTS → CODE_FILE `scripts/appliance/publish-seat-image.sh` (Signed GHCR publication independent of package releases)
- TESTS → TEST `tests/test_seat_image_trust.py` (Wrong-signature, digest and trust-rotation rejection)
- TESTS → TEST `tests/test_seat_image_update.py` (Failed admission preservation and independent offline restart across updates)
- TESTS → TEST `tests/test_seat_image_consent.py` (Consent before acquisition and no fallback)
- TESTS → TEST `tests/test_seat_image_build.py` (Offline assembly and guest boot contracts)
- TESTS → TEST `tests/test_seat_local_release.py` (Local cut identity and package release independence)
