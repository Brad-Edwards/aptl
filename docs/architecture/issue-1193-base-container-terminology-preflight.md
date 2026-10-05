# Issue #1193: Base Container Terminology Preflight

Issue #1193 is the contract for this terminology change. This note fixes the
concept boundary and compatibility guardrails before implementation. ADR-048
and ADR-051 already own the realization architecture; this issue does not make
a new source-route decision.

## Decision and boundaries

Call a node whose declared software, content, identities, and services are
applied onto a Docker base container a **base-container-materialized node**.
The node requires a real base image. Depending on admitted substrate policy,
that image may be a generic OS base or a verified backend-selected base. The
term describes where scenario state comes from, not the absence of Docker
images, the presence of a Compose service, or whether the whole graph uses
Compose. Use “base container” for the Docker object and “base image” for its
image artifact. Use “image-backed node” for the distinct admitted component
artifact route. Keep `dynamic-composition` as the RAES mechanism name.

ADR-048's title and original decision text are historical. Cite this definition
when discussing its current implementation and keep its ADR-051 partial
supersession visible. Current operator documentation, navigation, diagnostics,
and examples should use the new term; preserved historical titles, changelog
entries, old issue quotations, and versioned evidence should be explicitly
identified as historical rather than silently rewritten.

The selection invariant remains: a deployment node is base-container-
materialized only when it has runtime desired state and no entry in
`DeploymentRealizationSpec.images`. The RAES-side `_is_materializable_node()`
uses `os`, runtime, and absent node image. Keep these decisions aligned. An
image-backed node can still declare runtime inventory and receive literal-path
content. `_needs_compose()` also retains its empty-graph and capture-apparatus
behavior. A base container starts through Docker even when `compose up` has no
node service to start.

## Contract inventory and canonical owners

| Surface | Existing owner and constraint |
| --- | --- |
| RAES source and admission | ADR-051, `raes_image_realization.py`, `raes_realization.py`, `raes_realization_model.py`, and RAES artifact requirements own route selection, immutable substrate identity, and dynamic-composition disclosure. Rename descriptions without adding an APTL route enum, source flag, or replacement schema. |
| Typed deployment and selection | `core/deployment/realization.py` owns `DeploymentNodeRealization`, `DeploymentImageRealization`, `DeploymentContentRealization`, and `DeploymentRealizationSpec`; `_compose_image_free_realization.py`, `_compose_mixed_realization.py`, and `_compose_realization.py` own the existing subset and Compose dispatch. Preserve field meanings, `details()` keys, service scaling, port stripping, generated artifacts, and volume handling. `backend_base_image_ref` is an actual image reference, not a candidate for cosmetic replacement. The removed spec-level `image_free` flag must stay removed. |
| Content placement | `raes_placement_realization.py` sends **both** materialized and image-backed nodes through `resolve_image_free_content_placement()` for authored literal destinations. Give this helper a route-neutral name if renamed; retain source policy, project containment, exact pack digest checks, sensitivity, and the existing `DeploymentContentRealization` shape. The empty `volume_suffix` denotes literal placement, not a no-image assertion. |
| Base image and Docker | `raes_base_substrate.py`, `raes_materializer.py`, `_compose_generic_base_images.py`, `_compose_base_substrate.py`, `_compose_substrate_gate.py`, and `_compose_substrate_attestation.py` own OS selection, preparation, daemon qualification, immutable image start, and posture readback. Preserve their image identities and Docker command shape. |
| Networking, observation, persistence | `_compose_realization_networks.py`, `_compose_network_realization.py`, `_compose_base_substrate.py`, `_raes_observation_index.py`, `_raes_stateful_observation.py`, and `_raes_artifact_delivery_observation.py` own admitted attachments, receipts, readback, and generated-artifact observation. Preserve address sets, owned native IDs, and fail-closed missing-network behavior. `_compose_stateful_model.py` has a broader non-Compose consumer set that includes imageless consumers; do not relabel that set as base-container-only. |
| Exposed names and diagnostics | `validation/imagefree_gate.py` exports `image_free_violations`, `assert_image_free`, and `ImageFreeGateError`; `_compose_realization.py` re-exports underscore-prefixed helpers in `__all__`; tests import those helpers and the content resolver directly. The RAES diagnostic code `aptl.provisioner.image-free-content-unsupported` is a machine-readable contract. Inventory other downstream imports before moving modules or deleting names. If compatibility is needed, use thin aliases with documented deprecation and tests; do not duplicate logic. A diagnostic-code change needs an intentional mapping and regression coverage, since consumers may key on it. Operator-facing messages in the gate, content resolver, networking, artifact readback, and `LabResult` need the new wording. |
| Current documentation and workflow | `mkdocs.yml`, `docs/adrs/README.md`, `docs/components/appliance-boundary.md`, `docs/testing/boot-realization-coverage.md`, `docs/workshop/hosted-backup-seats.md`, `docker-compose.yml` comments, and `.github/workflows/checks.yml` comments are current-facing. Historical ADRs, architecture notes, reviews, and `CHANGELOG.md` retain provenance with an explicit terminology note or cross-reference where readers might mistake an old term for the current model. |

## Cross-cutting passage

This is a terminology change, so it needs no new auth endpoint, persistent
record, environment setting, or config field. If implementation touches a
boundary, it must pass its existing gate:

- **Admission and validation:** RAES parse/compile/plan, the existing typed
  deployment DTOs, `validation/imagefree_gate.py`, runtime-materialization
  preflight, and substrate daemon/attestation gates keep their current
  predicates. No duplicate validator or exception hierarchy.
- **Secrets and filesystem:** `raes_content_source_policy.py`,
  `core/credentials.py`, env-pack artifact resolution, `core/env.py`, and
  `valid_environment_variable_name()` remain authoritative. Do not move
  sensitive content into diagnostics. Keep environment values in private
  `--env-file` files through `_compose_base_substrate.py`, never `docker -e`
  values in process argv, logs, or error text.
- **Runtime authority:** Docker endpoint binding and backend `_run()` use the
  selected daemon; resource ownership, network binding, and substrate readback
  remain fail closed. Do not infer ownership or route from a renamed label,
  Compose stub, image tag, or container name.
- **Errors and observability:** `raes_diagnostics.diagnostic()` and
  `render_raes_diagnostics()`, `LabResult`, deployment errors, and the existing
  redaction/logging helpers own envelopes. Change human text deliberately;
  preserve or explicitly version stable diagnostic codes. Never expose raw
  environment, inspect payloads, or Docker stderr to improve wording.

The extension seam is the existing typed route and base-image policy:
`NodePlanningOptions.backend_base_image_ref` and the verified
`substrate_digests` passed to `realize()`. A future admitted base image or
another component image changes those inputs, not the meaning of the term or
the node-selection predicate. Keep the terminology independent of OS family,
scenario, package set, and whether Compose starts other nodes.

## Implementation guardrails and non-goals

Preserve the existing node selection, content placement, image preparation,
Docker start, Compose dispatch, network reconciliation, generated-artifact
delivery, observation, and deployment outcomes. Avoid a global string
replacement: `image`, `backing image`, `base image`, `image-backed`,
`imageless`, `non-Compose`, and `dynamic-composition` carry different facts.
Do not add a whole-graph boolean, another route selector, a second content
schema, a compatibility fork of the materializer, or a new diagnostic
framework. Do not change RAES, Docker, packaging, or scenario architecture.

Targeted regressions should pin route selection for mixed and empty graphs,
literal content delivery to both node routes, any retained import aliases,
and any changed diagnostic code or serialized field. Use
`bash tools/run-targeted-tests.sh` for changed tests, stage intended files,
and run `pre-commit run`; full suites and coverage belong in CI/CD per
`.ground-control.yaml` and `.gc/plan-rules.md`.
