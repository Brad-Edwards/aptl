"""Lab-managed CA + per-service certificates for the SOC stack (SEC-006).

Mirrors the result/error shape of :mod:`aptl.core.certs` (Wazuh INF-005)
but generates artifacts entirely in-process via the ``cryptography``
library. The Wazuh chain stays untouched per ADR-034 § Context.

Outputs land under ``config/soc_certs/`` (gitignored). The CA private key
and per-service private keys are control-plane secrets under ADR-029 —
never logged, never embedded in result envelopes, never copied into
``aptl.json`` or MCP JSON config. Public certificates are bind-mounted
read-only into client containers.

The service registry below is the extensibility seam called out in
ADR-034 § Decision: adding another SOC HTTPS service should be one more
:class:`ServiceCert` entry, not another generator or another CA.

Module layout: this file owns the public API (dataclasses + the
``ensure_soc_certs`` orchestrator + ``_generate_all`` generator).
Chain-validation helpers live in :mod:`aptl.core._soc_ca_chain`;
filesystem/path helpers live in :mod:`aptl.core._soc_ca_io`. The split
keeps each layer under SonarPython's file-size budget while letting the
public surface stay re-exported here.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from aptl.core._soc_ca_chain import _all_artifacts_present_and_consistent
from aptl.core._soc_ca_generation import (
    # Re-exported so the generator keeps its historical ``aptl.core.soc_ca``
    # name after the split.
    _generate_all as _generate_all,
)
from aptl.core._soc_ca_io import (
    LAB_CA_RELDIR,
    PathContainmentError,
    _canonical_output_dir,
)
from aptl.utils.logging import get_logger

log = get_logger("soc_ca")

# Re-exports for callers that still reach in through ``aptl.core.soc_ca``.
__all__ = (
    "CertResult",
    "LAB_CA_RELDIR",
    "PathContainmentError",
    "SOC_SERVICE_REGISTRY",
    "ServiceCert",
    "derive_soc_service_certs",
    "ensure_soc_certs",
    "soc_bundle_evidence",
)

# ---------------------------------------------------------------------------
# Public paths and dataclasses
# ---------------------------------------------------------------------------

_CA_KEY_NAME = "lab-ca.key"
_CA_CERT_NAME = "lab-ca.pem"


@dataclass(frozen=True)
class ServiceCert:  # NOSONAR python:S5663 - Python 3 dataclass; no need for explicit `object` base
    """One row of the SOC service certificate registry.

    Attributes:
        name: Subdirectory under the CA output dir; also the Docker
            service name used to derive the in-network DNS SAN.
        subject_cn: ``Subject CN`` for the issued cert. Conventional, not
            relied on for verification (SANs are what TLS actually checks).
        sans: SAN list. DNS hostnames as plain strings; IP literals are
            detected and emitted as IPAddress SAN entries.
        cert_filename: PEM cert filename inside ``<output>/<name>/``.
        key_filename: PEM private-key filename inside ``<output>/<name>/``.
        needs_keystore: ``True`` for Play-framework services (TheHive,
            Cortex) which consume a PKCS#12 keystore alongside the PEM
            files. Adds ``keystore.p12`` and ``keystore.p12.password``.
    """

    name: str
    subject_cn: str
    sans: tuple[str, ...]
    cert_filename: str = "server.pem"
    key_filename: str = "server.key"
    needs_keystore: bool = False


# Legacy in-tree fallback ONLY. An env-pack realization derives its SOC service
# certificate set from the declared certificate-bundle *outputs* (see
# ``derive_soc_service_certs``) so APTL never decides which services exist or
# what identities they carry — that is authored in the SDL. This table is kept
# solely for the in-tree ``aptl lab start`` path that has no realization spec to
# derive from; it is never the primary decision source (issue #875, SDL-authority
# class remediation).
SOC_SERVICE_REGISTRY: tuple[ServiceCert, ...] = (
    ServiceCert(
        name="misp",
        subject_cn="aptl-misp",
        sans=("misp", "localhost", "127.0.0.1"),
    ),
    ServiceCert(
        name="thehive",
        subject_cn="aptl-thehive",
        sans=("thehive", "localhost", "127.0.0.1"),
        needs_keystore=True,
    ),
    ServiceCert(
        name="cortex",
        subject_cn="aptl-cortex",
        sans=("cortex", "localhost", "127.0.0.1"),
        needs_keystore=True,
    ),
    ServiceCert(
        name="shuffle-frontend",
        subject_cn="aptl-shuffle-frontend",
        sans=("shuffle-frontend", "localhost", "127.0.0.1"),
    ),
)


def derive_soc_service_certs(
    output_paths: tuple[str, ...],
) -> tuple[ServiceCert, ...]:
    """Derive the SOC service certificate set from declared bundle outputs.

    The SDL authors *which* SOC services get certificates and *what* each needs
    as the certificate-bundle artifact's declared outputs — e.g.
    ``misp/server.pem``, ``thehive/keystore.p12``. APTL derives the request set
    from those paths instead of a hardcoded service registry, so it never decides
    the range's service identity (issue #875):

    - each first path segment names a service (root-level outputs like the CA's
      ``lab-ca.pem`` are not a service);
    - a ``.p12`` output for a service means it needs a PKCS#12 keystore;
    - SANs are the service's own DNS name plus host-loopback for local access.

    The subject CN is the conventional ``aptl-<service>`` (TLS verifies SANs, not
    CN). The per-service PKCS#12 requirement is derived here from the declared
    outputs; a first-class cert-request/keystore affordance is tracked upstream.
    """

    from pathlib import PurePosixPath

    files_by_service: dict[str, set[str]] = {}
    for raw in output_paths:
        parts = PurePosixPath(raw).parts
        # A root-level output (the CA) is not a per-service leaf.
        if len(parts) < 2:
            continue
        files_by_service.setdefault(parts[0], set()).add(parts[-1])
    return tuple(
        ServiceCert(
            name=service,
            subject_cn=f"aptl-{service}",
            sans=(service, "localhost", "127.0.0.1"),
            needs_keystore=any(name.endswith(".p12") for name in files),
        )
        for service, files in sorted(files_by_service.items())
    )


def soc_bundle_evidence(
    certs_dir: Path,
    output_paths: tuple[str, ...],
) -> dict[str, object] | None:
    """Return non-secret proof that a realized SOC bundle is consistent, or None.

    The SOC bundle is not the Wazuh ``root-ca.pem`` + ``*-key.pem`` shape -- it
    carries its own CA name, ``.key`` private keys, and PKCS#12 keystores with
    passphrase files -- so the Wazuh bundle validator cannot read it. Rather than
    let a certificate bundle be reported realized on file presence alone, this
    reuses the same chain check ``ensure_soc_certs`` uses: every leaf verifies
    against the on-disk CA, every key derives its cert's public key, and every
    keystore unlocks to a cert with the matching fingerprint (issue #875).

    Only the CA's public fingerprint leaves this boundary; no key material, no
    passphrase, and no path.
    """

    if not _all_artifacts_present_and_consistent(
        certs_dir,
        _CA_CERT_NAME,
        _CA_KEY_NAME,
        derive_soc_service_certs(output_paths),
    ):
        return None
    try:
        root = x509.load_pem_x509_certificate((certs_dir / _CA_CERT_NAME).read_bytes())
    except (OSError, ValueError):
        return None
    return {
        "public_root_sha256": root.fingerprint(hashes.SHA256()).hex(),
        "chain_valid": True,
        "san_valid": True,
    }


@dataclass
class CertResult:  # NOSONAR python:S5663 - Python 3 dataclass; no need for explicit `object` base
    """Outcome of :func:`ensure_soc_certs`.

    Mirrors :class:`aptl.core.certs.CertResult`: ``success`` is the
    pass/fail signal the orchestrator branches on; ``generated`` is
    informational (was new key material produced this run?).
    """

    success: bool
    generated: bool
    certs_dir: Path = Path()
    error: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ensure_soc_certs(
    project_dir: Path,
    services: tuple[ServiceCert, ...] = SOC_SERVICE_REGISTRY,
) -> CertResult:
    """Generate the lab CA + service certificates if any are missing.

    ``services`` is the set of per-service certificate requests to issue. An
    env-pack realization passes the set derived from the SDL's declared bundle
    outputs (:func:`derive_soc_service_certs`); the in-tree ``aptl lab start``
    path, which has no realization spec, falls back to
    :data:`SOC_SERVICE_REGISTRY` (issue #875).

    Returns a :class:`CertResult` with ``generated=False`` when every
    required artifact is already on disk; otherwise generates the missing
    pieces, writes them atomically with restrictive permissions, and
    returns ``generated=True``.

    The CA private key, each service private key, and each PKCS#12
    passphrase are written with mode ``0o600``. Public certs and PKCS#12
    keystores are ``0o644`` so a container process running as a non-root UID
    can still read them across a bind mount.

    Never logs PEM content, key paths, or passphrases. Failure messages
    cite only the SOC tool name and the affected layer.
    """
    try:
        output_dir = _canonical_output_dir(project_dir)
    except PathContainmentError as exc:
        log.exception("soc_cert_generation: %s", exc)
        return _fail_containment(project_dir / LAB_CA_RELDIR, exc)

    if _all_artifacts_present_and_consistent(
        output_dir, _CA_CERT_NAME, _CA_KEY_NAME, services
    ):
        log.info(
            "SOC stack lab CA already present and consistent at %s",
            output_dir,
        )
        return CertResult(success=True, generated=False, certs_dir=output_dir)

    log.info("Generating SOC stack lab CA + service certificates at %s", output_dir)
    return _generate_with_error_envelope(output_dir, services)


def _fail_containment(certs_dir: Path, exc: PathContainmentError) -> CertResult:
    """Build the :class:`CertResult` for a containment-check refusal.

    Kept as its own helper so the orchestrator's single-error-shape
    contract stays visible in one place — the message body is the
    exception itself, which is safe to surface (it names the rejected
    path, never key material).
    """
    return CertResult(
        success=False,
        generated=False,
        certs_dir=certs_dir,
        error=str(exc),
    )


def _generate_with_error_envelope(
    output_dir: Path, services: tuple[ServiceCert, ...]
) -> CertResult:
    """Wrap :func:`_generate_all` in the ADR-029 error-envelope policy.

    The cryptography stack raises a heterogeneous tree of exception
    classes (InvalidKey, UnsupportedAlgorithm, OSError from PKCS#12
    internals, etc.). The whole point of this layer is to convert ANY
    of them into a fatal :class:`CertResult` for the orchestrator while
    DROPPING the original exception message — payloads from cryptography
    / PKCS#12 paths can echo derived key material or PEM blocks (see
    ADR-029 § Secret at rest).

    Returns ``CertResult(success=True, generated=True)`` on success, or a
    failure result whose ``error`` field names the failing generator
    phase + exception class only.
    """
    try:
        _generate_all(output_dir, services)
    except PathContainmentError as exc:
        # Containment violation per-service subdir; the message itself
        # is safe (it names the rejected path, not key material).
        log.exception("soc_cert_generation: containment violation: %s", exc)
        return CertResult(
            success=False,
            generated=False,
            certs_dir=output_dir,
            error=f"SOC certificate generation failed: {exc}",
        )
    # Broad except is the ADR-029 contract: ANY cryptography failure
    # converts to a fatal CertResult (see docstring catalog).
    except Exception as exc:
        layer = _classify_failure_layer(exc)
        log.exception(
            "soc_cert_generation: %s failed: %s",
            layer, exc.__class__.__name__,
        )
        return CertResult(
            success=False,
            generated=False,
            certs_dir=output_dir,
            error=(
                f"SOC certificate generation failed in {layer}: "
                f"{exc.__class__.__name__}"
            ),
        )
    return CertResult(success=True, generated=True, certs_dir=output_dir)


def _classify_failure_layer(exc: BaseException) -> str:
    """Map an exception traceback to the cert-generation layer that
    raised it.

    ``traceback.extract_tb`` returns frames outermost → innermost, so
    iterating forward and returning the first ``soc_ca.py`` frame would
    always surface the outer ``ensure_soc_certs`` wrapper. Iterate in
    reverse so we report the actual failing inner phase (e.g.
    ``_build_server_cert``, ``_atomic_write``, ``_safe_service_subdir``)
    that operators need to inspect.
    """
    frames = traceback.extract_tb(exc.__traceback__)
    for frame in reversed(frames):
        if frame.filename.endswith("soc_ca.py") and frame.name:
            return frame.name.lstrip("_")
    return "soc_ca"
