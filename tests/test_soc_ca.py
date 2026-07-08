"""Tests for SOC stack lab-CA generation (SEC-006, ADR-034).

Tests are written FIRST (TDD). All certificate generation runs in-process
via the ``cryptography`` library — there are no docker/subprocess calls to
mock, only filesystem behaviour to assert.
"""

from __future__ import annotations

import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _san_dns(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(san.value.get_values_for_type(x509.DNSName))


def _san_ip(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]


# ---------------------------------------------------------------------------
# ensure_soc_certs — first-run generation
# ---------------------------------------------------------------------------


class TestFirstRunGeneration:
    def test_generates_ca_and_all_service_certs_on_fresh_dir(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        result = ensure_soc_certs(tmp_path)

        assert result.success is True
        assert result.generated is True

        ca_dir = tmp_path / LAB_CA_RELDIR
        assert (ca_dir / "lab-ca.pem").is_file()
        assert (ca_dir / "lab-ca.key").is_file()
        for svc in SOC_SERVICE_REGISTRY:
            svc_dir = ca_dir / svc.name
            assert (svc_dir / svc.cert_filename).is_file()
            assert (svc_dir / svc.key_filename).is_file()
            if svc.needs_keystore:
                assert (svc_dir / "keystore.p12").is_file()
                assert (svc_dir / "keystore.p12.password").is_file()

    def test_registry_covers_all_four_soc_tools(self):
        from aptl.core.soc_ca import SOC_SERVICE_REGISTRY

        names = {s.name for s in SOC_SERVICE_REGISTRY}
        assert names == {"misp", "thehive", "cortex", "shuffle-frontend"}

    def test_keystore_only_for_play_framework_services(self):
        from aptl.core.soc_ca import SOC_SERVICE_REGISTRY

        keystore = {s.name for s in SOC_SERVICE_REGISTRY if s.needs_keystore}
        assert keystore == {"thehive", "cortex"}

    def test_ca_cert_is_self_signed(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca = _load_cert(tmp_path / LAB_CA_RELDIR / "lab-ca.pem")
        assert ca.issuer == ca.subject

    def test_each_service_cert_is_signed_by_ca(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        ca = _load_cert(ca_dir / "lab-ca.pem")

        for svc in SOC_SERVICE_REGISTRY:
            cert = _load_cert(ca_dir / svc.name / svc.cert_filename)
            assert cert.issuer == ca.subject, f"{svc.name} not issued by lab CA"
            # The signature must verify against the CA's public key.
            ca.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                _padding_for(cert),
                cert.signature_hash_algorithm,
            )

    def test_sans_include_docker_dns_and_localhost(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        for svc in SOC_SERVICE_REGISTRY:
            cert = _load_cert(ca_dir / svc.name / svc.cert_filename)
            dns = _san_dns(cert)
            ips = _san_ip(cert)
            # ADR-034: SANs must cover Docker DNS + localhost
            assert svc.name.split("-")[0] in dns or svc.name in dns, (
                f"{svc.name} cert missing Docker DNS SAN; got dns={dns}"
            )
            assert "localhost" in dns, f"{svc.name} cert missing localhost SAN"
            assert "127.0.0.1" in ips, f"{svc.name} cert missing 127.0.0.1 SAN"

    def test_ca_not_after_is_about_ten_years_out(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca = _load_cert(tmp_path / LAB_CA_RELDIR / "lab-ca.pem")
        delta = ca.not_valid_after_utc - datetime.now(timezone.utc)
        # ten years ± 1 day for clock skew
        assert timedelta(days=10 * 365 - 1) <= delta <= timedelta(days=10 * 365 + 1)

    def test_service_certs_not_after_is_about_five_years_out(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        for svc in SOC_SERVICE_REGISTRY:
            cert = _load_cert(ca_dir / svc.name / svc.cert_filename)
            delta = cert.not_valid_after_utc - datetime.now(timezone.utc)
            assert timedelta(days=5 * 365 - 1) <= delta <= timedelta(days=5 * 365 + 1)

    def test_ca_has_basic_constraints_marking_it_as_ca(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca = _load_cert(tmp_path / LAB_CA_RELDIR / "lab-ca.pem")
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True

    def test_service_certs_have_server_auth_eku(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        for svc in SOC_SERVICE_REGISTRY:
            cert = _load_cert(ca_dir / svc.name / svc.cert_filename)
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku.value


# ---------------------------------------------------------------------------
# Permissions / secret-at-rest contract (ADR-029)
# ---------------------------------------------------------------------------


class TestPermissions:
    """Permission contract (ADR-029 § Secret at rest).

    - Output dir + per-service subdirs: ``0o700`` (host-side access control).
    - Public certs: ``0o644`` (operator-readable, mounted as RO).
    - Private keys and keystore password files: ``0o600``.
    - PKCS#12 keystores: ``0o644`` so non-root Play containers can read the
      bind-mounted file when their UID differs from the host user.
    """

    def test_output_dir_is_owner_traverseable_only(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        mode = stat.S_IMODE((tmp_path / LAB_CA_RELDIR).stat().st_mode)
        assert mode == 0o700, f"output dir mode {oct(mode)} != 0o700"

    def test_per_service_subdir_is_owner_traverseable_only(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        for svc in SOC_SERVICE_REGISTRY:
            mode = stat.S_IMODE((ca_dir / svc.name).stat().st_mode)
            assert mode == 0o700, f"{svc.name} dir mode {oct(mode)} != 0o700"

    def test_ca_private_key_is_owner_read_only(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        key_path = tmp_path / LAB_CA_RELDIR / "lab-ca.key"
        mode = stat.S_IMODE(key_path.stat().st_mode)
        assert mode == 0o600, f"CA key mode {oct(mode)} != 0o600"

    def test_service_private_keys_are_owner_read_only(self, tmp_path):
        """Server keys at 0600 — tight by intent per codex security
        finding. Services that need host-generated private key material through
        a non-root bind mount should consume the container-readable PKCS#12
        keystore path instead of widening raw PEM private keys."""
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        for svc in SOC_SERVICE_REGISTRY:
            key_path = ca_dir / svc.name / svc.key_filename
            mode = stat.S_IMODE(key_path.stat().st_mode)
            assert mode == 0o600, f"{svc.name} key mode {oct(mode)} != 0o600"

    def test_keystore_is_container_readable_and_password_file_is_owner_read_only(
        self, tmp_path
    ):
        """Keystore crosses a bind mount; password stays host-side env_file only."""
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        for svc in SOC_SERVICE_REGISTRY:
            if not svc.needs_keystore:
                continue
            keystore = ca_dir / svc.name / "keystore.p12"
            password = ca_dir / svc.name / "keystore.p12.password"
            keystore_mode = stat.S_IMODE(keystore.stat().st_mode)
            password_mode = stat.S_IMODE(password.stat().st_mode)
            assert keystore_mode == 0o644, (
                f"{svc.name} keystore.p12 mode {oct(keystore_mode)} != 0o644"
            )
            assert password_mode == 0o600, (
                f"{svc.name} keystore.p12.password mode {oct(password_mode)} != 0o600"
            )


class TestSymlinkContainmentPerService:
    """ADR-029 / codex security finding: a pre-planted symlink at
    ``config/soc_certs/<service>`` would otherwise let the generator
    write server keys outside the gitignored tree."""

    def test_refuses_per_service_subdir_pointing_outside_project(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        ca_dir = tmp_path / LAB_CA_RELDIR
        ca_dir.mkdir(parents=True, exist_ok=True)
        outside = tmp_path.parent / "soc_certs_outside_svc"
        outside.mkdir(exist_ok=True)
        # Pre-plant the symlink under the canonical svc name.
        (ca_dir / "misp").symlink_to(outside)

        result = ensure_soc_certs(tmp_path)

        assert result.success is False
        err = result.error.lower()
        assert any(w in err for w in ("refusing", "symlink", "escape", "containment"))
        # Nothing was written through the symlink.
        assert not (outside / "server.key").exists()


class TestEarlyReturnConsistency:
    """The 'all artifacts present' fast path must also validate the
    chain — codex review #2 against this PR called out that presence
    alone lets a partial-cleanup tree ship as 'ready' while clients
    trusting the on-disk CA cannot verify the on-disk leaves."""

    def test_keystore_with_stale_password_fails_consistency_check(self, tmp_path):
        """An attacker-or-bug-corrupted keystore.p12.password forces
        regeneration via the consistency path."""
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        first = ensure_soc_certs(tmp_path)
        assert first.generated is True

        ca_dir = tmp_path / LAB_CA_RELDIR
        pw_path = ca_dir / "thehive" / "keystore.p12.password"
        original_keystore = (ca_dir / "thehive" / "keystore.p12").read_bytes()

        # Corrupt the password — the keystore can no longer be unlocked
        # with what's on disk. Consistency check must catch this.
        pw_path.write_bytes(b"HTTPS_KEYSTORE_PASSWORD=wrong\n")

        second = ensure_soc_certs(tmp_path)
        assert second.success is True
        # Generator must have re-issued the keystore so the password
        # matches again.
        new_keystore = (ca_dir / "thehive" / "keystore.p12").read_bytes()
        assert new_keystore != original_keystore

    def test_service_key_cert_mismatch_triggers_regeneration(self, tmp_path):
        """If server.pem and server.key drift apart (e.g. partial
        write), the consistency check must regenerate the pair."""
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        first = ensure_soc_certs(tmp_path)
        assert first.generated is True

        ca_dir = tmp_path / LAB_CA_RELDIR
        # Swap MISP's server.key with Shuffle's server.key — they
        # don't match each other's certs. Read perms tighten on first
        # run (0600); reopen for read+write.
        misp_key = ca_dir / "misp" / "server.key"
        shuffle_key = ca_dir / "shuffle-frontend" / "server.key"
        misp_key.write_bytes(shuffle_key.read_bytes())

        second = ensure_soc_certs(tmp_path)
        assert second.success is True

        # Either the key was reverted (matched again) or the cert was
        # re-issued to match the swapped key. Either way, the on-disk
        # key + cert must derive the same public key now.
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_pem_x509_certificate(
            (ca_dir / "misp" / "server.pem").read_bytes()
        )
        key = serialization.load_pem_private_key(
            (ca_dir / "misp" / "server.key").read_bytes(), password=None
        )
        assert (
            key.public_key().public_numbers()
            == cert.public_key().public_numbers()
        )


class TestFailureContextInError:
    """Codex review #2: previously the error returned only
    ``ValueError`` (exception class), with no hint about which
    generator phase tripped. Operators need to know which artifact to
    inspect or delete."""

    def test_containment_failure_names_the_canonical_path(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        # Plant a symlink that escapes containment on a per-service
        # subdir (so the failure comes from _safe_service_subdir
        # rather than the top-level _canonical_output_dir).
        ca_dir = tmp_path / LAB_CA_RELDIR
        ca_dir.mkdir(parents=True, exist_ok=True)
        outside = tmp_path.parent / "soc_certs_outside_naming"
        outside.mkdir(exist_ok=True)
        (ca_dir / "misp").symlink_to(outside)

        result = ensure_soc_certs(tmp_path)
        assert result.success is False
        # The error preserves the canonical service path so the
        # operator can fix the right artifact.
        assert "misp" in result.error.lower()


class TestStaleCertConsistency:
    """Codex finding: presence-only idempotency lets a stale service cert
    + freshly regenerated CA ship "success" while clients trust a CA
    that did not issue the leaves."""

    def test_stale_service_cert_signed_by_old_ca_is_regenerated(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        # First run: writes the canonical CA + service certs.
        first = ensure_soc_certs(tmp_path)
        assert first.success is True

        ca_dir = tmp_path / LAB_CA_RELDIR
        misp_cert = ca_dir / "misp" / "server.pem"
        stale_fingerprint_before = _load_cert(misp_cert).fingerprint(hashes.SHA256())

        # Simulate the partial-cleanup case: nuke the CA but keep the
        # service leaves. A new run should detect the chain mismatch
        # and rebuild the leaves to be signed by the new CA.
        (ca_dir / "lab-ca.pem").unlink()
        (ca_dir / "lab-ca.key").unlink()

        second = ensure_soc_certs(tmp_path)
        assert second.success is True

        new_ca = _load_cert(ca_dir / "lab-ca.pem")
        new_misp = _load_cert(misp_cert)
        assert new_misp.issuer == new_ca.subject, (
            "stale MISP cert was kept; clients trusting the new CA would "
            "fail to verify it"
        )
        # Fingerprint must have changed.
        assert new_misp.fingerprint(hashes.SHA256()) != stale_fingerprint_before

    def test_regenerated_leaf_invalidates_old_keystore(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        first = ensure_soc_certs(tmp_path)
        assert first.success is True

        ca_dir = tmp_path / LAB_CA_RELDIR
        thehive_keystore = ca_dir / "thehive" / "keystore.p12"
        assert thehive_keystore.is_file()
        original_keystore = thehive_keystore.read_bytes()

        # Same partial-cleanup setup → CA regenerated, leaves invalidated,
        # keystore must therefore be re-issued from the new pair.
        (ca_dir / "lab-ca.pem").unlink()
        (ca_dir / "lab-ca.key").unlink()
        second = ensure_soc_certs(tmp_path)
        assert second.success is True
        assert thehive_keystore.is_file()
        assert thehive_keystore.read_bytes() != original_keystore


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_rerun_is_a_noop_when_all_artifacts_present(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        first = ensure_soc_certs(tmp_path)
        assert first.generated is True

        ca_path = tmp_path / LAB_CA_RELDIR / "lab-ca.pem"
        original_bytes = ca_path.read_bytes()

        second = ensure_soc_certs(tmp_path)
        assert second.success is True
        assert second.generated is False
        # CA was not rewritten
        assert ca_path.read_bytes() == original_bytes


# ---------------------------------------------------------------------------
# Containment / path safety (ADR-028)
# ---------------------------------------------------------------------------


class TestContainment:
    def test_refuses_when_output_dir_resolves_outside_project(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, ensure_soc_certs

        # Plant a symlink at the canonical output location pointing outside
        # the project root. The first run should refuse rather than write
        # CA material through the symlink.
        outside = tmp_path.parent / "soc_certs_outside"
        outside.mkdir(exist_ok=True)
        canonical = tmp_path / LAB_CA_RELDIR
        canonical.parent.mkdir(parents=True, exist_ok=True)
        canonical.symlink_to(outside)

        result = ensure_soc_certs(tmp_path)

        assert result.success is False
        # Containment refusal: "resolves to … refusing to generate keys
        # through a symlinked path" is the canonical message. Match any
        # of the marker words so reshuffling the prose doesn't churn the test.
        err = result.error.lower()
        assert any(w in err for w in ("containment", "escape", "refusing", "symlink"))
        # Nothing was written through the symlink
        assert not (outside / "lab-ca.pem").exists()


# ---------------------------------------------------------------------------
# PKCS#12 keystore correctness (TheHive / Cortex)
# ---------------------------------------------------------------------------


class TestKeystore:
    def test_keystore_can_be_unlocked_with_password_file_and_contains_cert(self, tmp_path):
        from aptl.core.soc_ca import LAB_CA_RELDIR, SOC_SERVICE_REGISTRY, ensure_soc_certs

        ensure_soc_certs(tmp_path)
        ca_dir = tmp_path / LAB_CA_RELDIR
        for svc in SOC_SERVICE_REGISTRY:
            if not svc.needs_keystore:
                continue
            keystore = (ca_dir / svc.name / "keystore.p12").read_bytes()
            pw_blob = (ca_dir / svc.name / "keystore.p12.password").read_text().strip()
            # env_file format: ``HTTPS_KEYSTORE_PASSWORD=<value>``
            assert pw_blob.startswith("HTTPS_KEYSTORE_PASSWORD="), (
                f"{svc.name} keystore.p12.password must be in env_file "
                f"format; got {pw_blob!r}"
            )
            password = pw_blob.split("=", 1)[1]
            assert password, f"{svc.name} keystore password value empty"
            private_key, cert, _addl = pkcs12.load_key_and_certificates(
                keystore, password.encode()
            )
            assert private_key is not None
            assert cert is not None
            # The cert inside the keystore matches the on-disk PEM cert
            on_disk = _load_cert(ca_dir / svc.name / svc.cert_filename)
            assert cert.fingerprint(hashes.SHA256()) == on_disk.fingerprint(hashes.SHA256())


# ---------------------------------------------------------------------------
# Helper: RSA-vs-EC padding for signature verification
# ---------------------------------------------------------------------------


def _padding_for(cert: x509.Certificate):
    """Return the signature padding appropriate to ``cert``'s public key type."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return padding.PKCS1v15()
    pytest.fail(f"Unexpected key type {type(pub)} — extend the test helper")
