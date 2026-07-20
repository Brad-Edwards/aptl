"""Experiment-admission diagnostics and the fail-closed rejection signal.

ADR-047 "Error envelope": admission normalizes every ACES/pydantic failure
into redacted :class:`aces_contracts.diagnostics.Diagnostic` values in one
``experiment-admission`` domain, and never lets a raw exception string
(which for pydantic ``ValidationError`` embeds the rejected ``input_value``,
and for ``ExperimentSpecValidationError`` wraps that same string via
``str()``) escape into a diagnostic. See the ACES API reference's
"Diagnostics" section for the failure shapes this module normalizes:
a pydantic ``ValidationError`` (and ``ExperimentSpecValidationError``, which
wraps one but must be unwrapped through ``__cause__`` rather than
stringified), ``aces_sdl`` ``SDLParseError``/``SDLValidationError``/
``SDLInstantiationError`` (already developer-authored, safe-to-pass-through
text), and a pass-through ``Diagnostic`` (or tuple of them) produced by an
ACES API that already returns the canonical shape (e.g.
``validate_associated_artifact_manifest``, ``run_reference_processor.diagnostics``).

``SDLInstantiationError`` (Stage 3 / EXP-002 apparatus admission) is what
``aces_processor.reference.run_reference_processor`` raises when a
condition's parameter binding is structurally broken (missing/unused/
undeclared target) — verified live against aces-sdl 0.23.1; the ACES API
reference doc consulted while building Stage 1 did not document this shape
because nothing before Stage 3 called ``run_reference_processor`` with
non-empty ``parameters``. It carries the same safe ``errors: list[str]``
shape as ``SDLValidationError`` (ACES-authored text naming the rejected
parameter *name*, never the bound *value*), so it is normalized identically.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import pydantic
from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.experiment_spec import ExperimentSpecValidationError
from aces_sdl import SDLInstantiationError, SDLParseError, SDLValidationError

from aptl.utils.redaction import redact

EXPERIMENT_ADMISSION_DOMAIN = "experiment-admission"
EXPERIMENT_ADMISSION_STAGE_LABEL = "Experiment admission failed"

# Heuristic scrub for a POSIX-looking absolute path embedded in otherwise
# developer-authored, pass-through SDL diagnostic text (ADR-047: "still
# avoid embedding any absolute path present in the text"). SDL diagnostic
# messages are safe by construction *for text ACES itself generates*, but a
# scenario document's own authored content can flow into a semantic-
# validation message, so this is defense in depth rather than the primary
# control. Matches a leading `/` followed by at least one more path
# separator so a bare `/` or a single URL-path segment is left alone.
_ABSOLUTE_PATH_RE = re.compile(r"/(?:[\w.\-]+/)+[\w.\-]*")
_PATH_PLACEHOLDER = "[PATH]"


class AdmissionRejection(Exception):
    """Fail-closed admission signal carrying already-safe diagnostics.

    ``diagnostics`` is exactly what it says: a tuple of already-redacted,
    already-safe :class:`Diagnostic` values (typically produced by
    :func:`normalize_aces_failure`). Callers should render/log via
    ``diagnostics``, not via ``str(exc)`` — the exception message is
    deliberately generic and carries no document content.
    """

    def __init__(self, diagnostics: Iterable[Diagnostic]) -> None:
        diagnostics_tuple = tuple(diagnostics)
        self.diagnostics: tuple[Diagnostic, ...] = diagnostics_tuple
        super().__init__(
            f"experiment admission rejected: {len(diagnostics_tuple)} diagnostic(s)"
        )


def diagnostic(
    code: str, address: str, message: str, *, severity: Severity = Severity.ERROR
) -> Diagnostic:
    """Build one redacted experiment-admission :class:`Diagnostic`.

    Mirrors ``aptl.backends.aces_diagnostics.diagnostic()`` but fixed to the
    ``experiment-admission`` domain. ``message`` is passed through
    :func:`redact` as defense in depth even though every caller in this
    package constructs it from safe, non-document-derived text.
    """
    return Diagnostic(
        code=code,
        domain=EXPERIMENT_ADMISSION_DOMAIN,
        address=address,
        message=redact(message),
        severity=severity,
    )


def _scrub_absolute_paths(text: str) -> str:
    return _ABSOLUTE_PATH_RE.sub(_PATH_PLACEHOLDER, text)


def _safe_loc_address(base_address: str, loc: tuple[object, ...]) -> str:
    if not loc:
        return base_address
    suffix = ".".join(str(part) for part in loc)
    return f"{base_address}.{suffix}"


def _diagnostics_from_pydantic_errors(
    errors: Iterable[dict[str, object]], *, address: str, code: str
) -> tuple[Diagnostic, ...]:
    """Build one Diagnostic per pydantic error, keeping ONLY loc/type/msg.

    ``input``, ``url``, and ``ctx`` are dropped unconditionally: ``input``
    is the rejected value itself (can carry an injected secret), ``url``
    is a pydantic.dev documentation link, and ``ctx`` can echo the input
    back inside its own values.
    """
    built: list[Diagnostic] = []
    for error in errors:
        loc = error.get("loc") or ()
        error_type = error.get("type", "validation-error")
        msg = error.get("msg", "validation failed")
        safe_address = _safe_loc_address(address, tuple(loc))  # type: ignore[arg-type]
        built.append(
            diagnostic(code, safe_address, f"{error_type}: {msg}")
        )
    return tuple(built)


def normalize_aces_failure(
    exc: BaseException | Diagnostic | tuple[Diagnostic, ...],
    *,
    address: str,
    code: str,
) -> tuple[Diagnostic, ...]:
    """Normalize one ACES/pydantic failure into safe :class:`Diagnostic` values.

    Handles exactly the shapes ADR-047 documents:

    * a pydantic ``ValidationError`` (structured; ``.errors()`` is used,
      ``input``/``url``/``ctx`` are dropped);
    * an ``ExperimentSpecValidationError``, which wraps a pydantic
      ``ValidationError`` via ``str()`` — its own message/``str()`` is
      NEVER read. When ``__cause__`` is the wrapped ``ValidationError`` its
      structured errors are used exactly like the direct case; otherwise
      (e.g. a YAML-shape rejection with no informative cause) a single
      generic, safe diagnostic is produced;
    * ``aces_sdl`` ``SDLParseError``/``SDLValidationError``/
      ``SDLInstantiationError`` — developer-authored text, passed through
      (with an absolute-path scrub applied as defense in depth);
    * a ``Diagnostic`` or a tuple of ``Diagnostic`` — passed through
      unchanged (an ACES API that already returns the canonical shape).
    """
    if isinstance(exc, Diagnostic):
        return (exc,)
    if isinstance(exc, tuple):
        return exc

    if isinstance(exc, pydantic.ValidationError):
        return _diagnostics_from_pydantic_errors(exc.errors(), address=address, code=code)

    if isinstance(exc, ExperimentSpecValidationError):
        cause = exc.__cause__
        if isinstance(cause, pydantic.ValidationError):
            return _diagnostics_from_pydantic_errors(
                cause.errors(), address=address, code=code
            )
        return (
            diagnostic(
                code,
                address,
                "experiment specification document failed to parse or validate",
            ),
        )

    if isinstance(exc, SDLParseError):
        if exc.diagnostics:
            return tuple(
                diagnostic(code, address, _scrub_absolute_paths(item.message))
                for item in exc.diagnostics
            )
        return (diagnostic(code, address, _scrub_absolute_paths(exc.details)),)

    if isinstance(exc, (SDLValidationError, SDLInstantiationError)):
        return tuple(
            diagnostic(code, address, _scrub_absolute_paths(message))
            for message in exc.errors
        )

    # Fail closed on any unrecognized exception shape: never fall back to
    # str(exc) — an exception type outside the four documented shapes has
    # no proven-safe rendering.
    return (diagnostic(code, address, "admission failed: unrecognized validation failure"),)
