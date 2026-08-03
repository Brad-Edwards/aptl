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

# APP-3 — Signed disposable appliance release envelope

## Statement

APTL shall assemble and verify a signed, versioned appliance release envelope that binds an immutable golden guest disk to the exact APTL source revision and version, staged participant profile and asset-lock identities, accepted qualification evidence, appliance boundary policy and helper-image digests, supported delivery adapters, and explicit host prerequisites; release verification shall fail closed on unsafe references, unknown fields, duplicate artifacts, digest or signature mismatch, missing offline inputs, golden-state contamination, insufficient multi-machine qualification, or an attempted in-place upgrade.

## Rationale

Issue #823 supplies the release artifact consumed by the host launcher in issue #824 and the hosted per-seat adapter in issue #825. APP-1 remains the boundary-enforcement authority and APP-2 remains the bounded participant-profile authority; this requirement binds those existing contracts into one immutable release unit without duplicating their schemas.

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `823` (Issue 823: signed disposable appliance release envelope)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/manifest.py` (Signed appliance release manifest)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/build.py` (Appliance release builder)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/offline.py` (Offline appliance payload staging)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Lab appliance lifecycle integration)
- IMPLEMENTS → CODE_FILE `src/aptl/appliance/launch.py` (Disposable appliance launcher)
- TESTS → TEST `tests/test_appliance_build.py` (Appliance builder tests)
- TESTS → TEST `tests/test_appliance_release_manifest.py` (Appliance release manifest tests)
- IMPLEMENTS → DOCUMENTATION `docs/reference/appliance-release.md` (Appliance release operator reference)
- TESTS → TEST `tests/test_appliance_offline_payload.py` (Offline payload tests)
- TESTS → TEST `tests/test_appliance_offline_start.py` (Offline start tests)
- IMPLEMENTS → CODE_FILE `appliance/guest/provision-offline.sh` (Offline appliance guest provisioning)
- TESTS → TEST `tests/test_appliance_guest_assets.py` (Appliance guest asset tests)
- TESTS → TEST `tests/test_appliance_cli.py` (Appliance CLI tests)
