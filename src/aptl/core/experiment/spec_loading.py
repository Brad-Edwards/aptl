"""Bounded, hardened loading of ACES artifacts from resolver bytes.

ADR-047 "ACES contracts remain authoritative": the root enters through
``parse_experiment_spec``; task/capture-spec payloads validate through the
exported ``ExperimentTaskModel``/``ExperimentCaptureSpecModel`` surfaces;
import-free scenario material is parsed from resolver-owned bytes with
``aces_sdl.parse_sdl``. APTL does not define a local authoring-input, task,
capture, or scenario model — every function here returns the ACES object
directly.

Every loader here takes ``data: bytes`` (never a path) — the caller is
expected to have already produced those bytes through
``aptl.core.experiment.resolver`` (one-open, no-follow, digest-verified).
Nothing in this module reopens a path.

Two parser-hardening gaps are closed before ANY ACES/pydantic model ever
sees the payload (ADR-047 "Input shape" / "Gotchas"):

* ``parse_experiment_spec`` uses ``yaml.safe_load``, which silently keeps
  the LAST of a duplicate mapping key instead of rejecting the ambiguity.
  A narrow duplicate-key-rejecting YAML preflight runs first.
* ``load_associated_artifact_manifest_json`` and the task/capture-spec
  loaders here use JSON; a duplicate JSON object member is rejected the
  same way ``load_associated_artifact_manifest_json`` already does.

Every failure — parser preflight, YAML/JSON decode, or the underlying ACES
validator — is normalized through
:func:`aptl.core.experiment.errors.normalize_aces_failure` and raised as
:class:`aptl.core.experiment.errors.AdmissionRejection`. In particular,
``ExperimentSpecValidationError``'s ``str()`` (which embeds pydantic's
``input_value``) is never read.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import BinaryIO

import yaml
from aces_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    AssociatedArtifactValidationLimits,
    validate_associated_artifact_manifest,
)
from aces_contracts.contracts import ExperimentCaptureSpecModel, ExperimentTaskModel
from aces_contracts.experiment_spec import (
    ExperimentSpecModel,
    ExperimentSpecValidationError,
    parse_experiment_spec,
)
from aces_sdl import SDLParseError, SDLValidationError, parse_sdl
from aces_sdl.canonical import SDLCanonicalDigest, canonical_sdl_digest
from aces_sdl.scenario import Scenario
from pydantic import ValidationError as PydanticValidationError

from aptl.core.experiment.errors import AdmissionRejection, diagnostic, normalize_aces_failure
from aptl.core.experiment.policy import AdmissionPolicy

_ADDRESS_ROOT = "root"
_ADDRESS_TASK = "task"
_ADDRESS_CAPTURE_SPEC = "capture_spec"
_ADDRESS_SCENARIO = "scenario"

_CODE_ROOT_INVALID = "aptl.experiment-admission.root-invalid"
_CODE_TASK_INVALID = "aptl.experiment-admission.task-invalid"
_CODE_CAPTURE_SPEC_INVALID = "aptl.experiment-admission.capture-spec-invalid"
_CODE_SCENARIO_INVALID = "aptl.experiment-admission.scenario-invalid"
_CODE_SCENARIO_IMPORTS_UNSUPPORTED = "aptl.experiment-admission.scenario-imports-unsupported"


# ---------------------------------------------------------------------------
# Shared bounded-decode + duplicate-key preflight helpers
# ---------------------------------------------------------------------------


def _reject(code: str, address: str, message: str) -> AdmissionRejection:
    return AdmissionRejection((diagnostic(code, address, message),))


def _decode_bounded_utf8(data: bytes, *, max_bytes: int, address: str, code: str) -> str:
    if len(data) > max_bytes:
        raise _reject(code, address, "document exceeds the configured byte limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _reject(code, address, "document is not valid UTF-8") from exc
    if "\x00" in text:
        raise _reject(code, address, "document must not contain a NUL byte")
    return text


class _DuplicateKeyRejectingLoader(yaml.SafeLoader):
    """A ``SafeLoader`` that raises on a duplicate YAML mapping key.

    Stock ``yaml.safe_load`` (what ``parse_experiment_spec`` uses)
    silently keeps the LAST of a duplicate key instead of rejecting the
    ambiguity (ADR-047 gotcha). This loader is used ONLY for the
    preflight pass — the result is discarded and ``parse_experiment_spec``
    is still the sole authority for the actual model.
    """


def _construct_mapping_no_duplicates(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_DuplicateKeyRejectingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_duplicates
)


def _yaml_duplicate_key_preflight(text: str, *, address: str, code: str) -> None:
    """Reject a duplicate mapping key or a multi-document stream.

    ``yaml.load`` (used with any ``Loader``, including this one) already
    raises ``ComposerError`` for a multi-document stream, since it calls
    the loader's ``get_single_data()``. The result is intentionally
    discarded: this is a preflight, not a second parse path — the public
    ACES loader remains the sole model authority.
    """
    try:
        yaml.load(text, Loader=_DuplicateKeyRejectingLoader)
    except yaml.YAMLError as exc:
        raise _reject(
            code, address, "document failed the duplicate-key/single-document preflight"
        ) from exc


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """``object_pairs_hook`` mirroring ``load_associated_artifact_manifest_json``'s
    own duplicate-member rejection, reused here for task/capture-spec JSON."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _load_bounded_json(
    data: bytes, *, policy: AdmissionPolicy, address: str, code: str
) -> object:
    text = _decode_bounded_utf8(data, max_bytes=policy.max_artifact_bytes, address=address, code=code)
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_json_members)
    except ValueError as exc:
        raise _reject(
            code, address, "document failed the duplicate-key/JSON preflight"
        ) from exc


# ---------------------------------------------------------------------------
# Public loaders
# ---------------------------------------------------------------------------


def load_experiment_root(data: bytes, *, policy: AdmissionPolicy) -> ExperimentSpecModel:
    """Bounded, hardened load of the root ``experiment-authoring-input/v1`` document."""
    text = _decode_bounded_utf8(
        data, max_bytes=policy.max_root_bytes, address=_ADDRESS_ROOT, code=_CODE_ROOT_INVALID
    )
    _yaml_duplicate_key_preflight(text, address=_ADDRESS_ROOT, code=_CODE_ROOT_INVALID)
    try:
        return parse_experiment_spec(text)
    except ExperimentSpecValidationError as exc:
        raise AdmissionRejection(
            normalize_aces_failure(exc, address=_ADDRESS_ROOT, code=_CODE_ROOT_INVALID)
        ) from exc


def load_task(data: bytes, *, policy: AdmissionPolicy) -> ExperimentTaskModel:
    """Bounded, hardened load of an ``experiment-task/v1`` artifact (JSON)."""
    payload = _load_bounded_json(
        data, policy=policy, address=_ADDRESS_TASK, code=_CODE_TASK_INVALID
    )
    try:
        return ExperimentTaskModel.model_validate(payload)
    except PydanticValidationError as exc:
        raise AdmissionRejection(
            normalize_aces_failure(exc, address=_ADDRESS_TASK, code=_CODE_TASK_INVALID)
        ) from exc


def load_capture_spec(data: bytes, *, policy: AdmissionPolicy) -> ExperimentCaptureSpecModel:
    """Bounded, hardened load of an ``experiment-capture-spec/v1`` artifact (JSON)."""
    payload = _load_bounded_json(
        data, policy=policy, address=_ADDRESS_CAPTURE_SPEC, code=_CODE_CAPTURE_SPEC_INVALID
    )
    try:
        return ExperimentCaptureSpecModel.model_validate(payload)
    except PydanticValidationError as exc:
        raise AdmissionRejection(
            normalize_aces_failure(exc, address=_ADDRESS_CAPTURE_SPEC, code=_CODE_CAPTURE_SPEC_INVALID)
        ) from exc


def parse_scenario_bytes(
    data: bytes, *, policy: AdmissionPolicy
) -> tuple[Scenario, SDLCanonicalDigest]:
    """Bounded parse of import-free SDL scenario bytes plus its canonical digest.

    ``aces_sdl.parse_sdl`` is called with ``path=None`` ALWAYS — never the
    resolver's original path — so a symlink swap after the resolver's
    single open cannot change what gets parsed (ADR-047 "never hand the
    original untrusted path to ``parse_sdl_file``"). This has a load-
    bearing side effect: at the locked ACES version, ``parse_sdl(text,
    path=None)`` itself raises ``SDLParseError`` before returning when the
    document declares a non-empty ``imports:`` list, because import
    resolution requires file-backed parsing. The explicit
    ``scenario.imports`` check below is kept as an independent, defense-
    in-depth fail-closed guard rather than relying solely on that
    implementation detail.
    """
    text = _decode_bounded_utf8(
        data, max_bytes=policy.max_artifact_bytes, address=_ADDRESS_SCENARIO, code=_CODE_SCENARIO_INVALID
    )
    try:
        scenario = parse_sdl(text)
    except (SDLParseError, SDLValidationError) as exc:
        raise AdmissionRejection(
            normalize_aces_failure(exc, address=_ADDRESS_SCENARIO, code=_CODE_SCENARIO_INVALID)
        ) from exc

    if scenario.imports:
        raise _reject(
            _CODE_SCENARIO_IMPORTS_UNSUPPORTED,
            f"{_ADDRESS_SCENARIO}.imports",
            "scenario declares imports, which admission does not resolve in this release",
        )

    return scenario, canonical_sdl_digest(scenario)


def validate_associated_artifacts(
    manifest: AssociatedArtifactManifestModel,
    *,
    parent: object,
    artifact_readers: Mapping[str, BinaryIO],
    limits: AssociatedArtifactValidationLimits,
) -> None:
    """Validate an associated-artifact manifest and fail closed on any error.

    Thin wiring over ``validate_associated_artifact_manifest`` (which
    itself never raises for content — an empty diagnostics tuple means
    valid). Any error-severity diagnostic in the result is promoted to
    :class:`AdmissionRejection`; the diagnostics it returns are already
    the safe canonical shape, so they are used unchanged.
    """
    diagnostics = validate_associated_artifact_manifest(
        manifest, parent=parent, artifact_readers=artifact_readers, limits=limits
    )
    errors = tuple(item for item in diagnostics if item.is_error)
    if errors:
        raise AdmissionRejection(errors)
