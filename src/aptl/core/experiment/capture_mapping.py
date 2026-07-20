"""ACES capture-requirement terms -> APTL capture-owner mapping (ADR-047
"Apparatus and capture capability admission").

This is the ONE code-owned mapping from ``ExperimentCaptureRequirementModel``
terms (``capture_kind``, ``capture_scope``, ``expected_media_types``,
``integrity_requirements``) to an existing APTL capture owner
(``collectors.py``, MCP/Kali capture, runtime snapshots, orchestration/
evaluation history). Admission and later execution share it. It describes
SUPPORT only — it never replaces the ACES capture-spec model, and it never
maps an unknown term to a collector name, import, backend method, or shell
command (ADR-047 "Apparatus capability admission").

FAIL-CLOSED BASELINE (the load-bearing rule for #438 / EXP-002): a capture
requirement is admitted ONLY when :data:`SUPPORTED_CAPTURE_CAPABILITIES`
declares evidence-backed support AND the resolved backend manifest's
``observation`` capability actually declares the matching channel/media/
sealing vocabulary. The mere existence of a best-effort collector function
is NEVER evidence of support — ``aptl.core.collectors`` collectors are
best-effort primitives that often collapse failure into an empty result
(ADR-047 Gotchas), and admitting on their presence would silently promise
evidence collection never verified end-to-end.

``create_aptl_manifest().observation`` is currently ``None`` (verified live
against aces-sdl 0.23.1 — see the ACES API reference consulted for Stage 3,
section 11). Because of that, :data:`SUPPORTED_CAPTURE_CAPABILITIES` is
EMPTY for #438: there is no honest backend observation declaration yet for
any entry to point at. EXP-010 (#752) is the extension seam — it must add
BOTH an honest ``create_aptl_manifest().observation`` declaration (naming
the real, verified channel/media/sealing vocabulary APTL's capture owners
actually provide) AND the corresponding :class:`CaptureCapability` entries
here, together. Adding one without the other is exactly the failure mode
this module exists to prevent.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from aces_backend_protocols.manifest import BackendManifest
from aces_contracts.contracts import ExperimentCaptureRequirementModel, ExperimentCaptureSpecModel

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.errors import AdmissionRejection, diagnostic
from aptl.core.experiment.policy import AdmissionPolicy

_CODE_CAPTURE_UNSUPPORTED = "aptl.experiment-admission.capture-requirement-unsupported"


@dataclass(frozen=True)
class CaptureCapability:
    """One evidence-backed ``(capture_kind, capture_scope)`` -> APTL owner entry.

    ``media_types``/``integrity_requirements`` further narrow support: a
    requirement is only covered when its ``expected_media_types`` and
    ``integrity_requirements`` are each a SUBSET of what this entry
    declares (never the reverse — a requirement asking for MORE than the
    entry covers is not admitted by it). ``capture_owner`` is a stable,
    human-readable identifier for the APTL capture owner (e.g. a
    ``module.function`` path in ``collectors.py`` or an MCP/Kali capture
    owner name) — never something admission itself resolves to an import,
    exec, or shell command.
    """

    capture_kind: str
    capture_scope: str
    media_types: frozenset[str]
    integrity_requirements: frozenset[str]
    capture_owner: str


#: Versioned, evidence-backed support table. EMPTY for #438 — see the
#: module docstring. EXP-010 (#752) is the only authorized place to add an
#: entry, and only alongside an honest, verified
#: ``create_aptl_manifest().observation`` declaration.
SUPPORTED_CAPTURE_CAPABILITIES: tuple[CaptureCapability, ...] = ()


def _resolve_capture_owner(
    requirement: ExperimentCaptureRequirementModel, backend_manifest: BackendManifest
) -> str | None:
    """Return the evidence-backed capture owner for requirement, or None if unsupported."""
    observation = backend_manifest.observation
    if observation is None:
        return None
    requirement_media_types = frozenset(requirement.expected_media_types)
    requirement_integrity = frozenset(requirement.integrity_requirements)
    for capability in SUPPORTED_CAPTURE_CAPABILITIES:
        if capability.capture_kind != requirement.capture_kind:
            continue
        if capability.capture_scope != requirement.capture_scope:
            continue
        if not requirement_media_types.issubset(capability.media_types):
            continue
        if not requirement_integrity.issubset(capability.integrity_requirements):
            continue
        if capability.capture_kind not in observation.supported_capture_kinds:
            continue
        if not requirement_media_types.issubset(observation.supported_media_types):
            continue
        return capability.capture_owner
    return None


def map_capture_requirements(
    capture_specs: Iterable[ExperimentCaptureSpecModel],
    *,
    backend_manifest: BackendManifest | None = None,
    policy: AdmissionPolicy,
) -> Mapping[str, str]:
    """Map every capture requirement in ``capture_specs`` to its APTL owner.

    Raises :class:`~aptl.core.experiment.errors.AdmissionRejection` (fail
    closed, naming the unsupported ``capture_kind``/``capture_scope``) the
    moment ANY requirement across ANY spec is not evidence-backed —
    admission is all-or-nothing, never a partial mapping. An empty
    ``capture_specs`` iterable (no capture spec resolved at all) maps to an
    empty result without rejecting; ``ExperimentCaptureSpecModel`` itself
    requires at least one entry in ``capture_requirements``, so an
    individual resolved spec can never itself be "empty".
    """
    # reserved: no capture-specific limit exists yet.
    del policy

    manifest = backend_manifest if backend_manifest is not None else create_aptl_manifest()
    result: dict[str, str] = {}
    diagnostics = []
    for spec in capture_specs:
        for requirement_id, requirement in spec.capture_requirements.items():
            address = f"capture_spec.{spec.capture_spec_id}.capture_requirements.{requirement_id}"
            owner = _resolve_capture_owner(requirement, manifest)
            if owner is None:
                diagnostics.append(
                    diagnostic(
                        _CODE_CAPTURE_UNSUPPORTED,
                        address,
                        "capture requirement (capture_kind="
                        f"{requirement.capture_kind!r}, capture_scope={requirement.capture_scope!r}) "
                        "is not evidence-backed by a declared backend observation capability",
                    )
                )
                continue
            result[f"{spec.capture_spec_id}.{requirement_id}"] = owner

    if diagnostics:
        raise AdmissionRejection(tuple(diagnostics))
    return result
