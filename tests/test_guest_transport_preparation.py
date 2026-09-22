"""Management publication binds public keys and the complete guest identity."""

from pathlib import Path

import pytest


def test_enrollment_accepts_key_comments_without_authorized_keys_injection():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from aptl.workbench.dispatch import key_fingerprint, restricted_key

    key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )
    assert key_fingerprint(key + " owner@host") == key_fingerprint(key)
    line = restricted_key(
        public_key=key + " harmless comment",
        executable=Path("/usr/bin/aptl"),
        binding=Path("/srv/binding.json"),
        grant_id="red-1",
    )
    assert line.endswith(key + "\n")
    assert "--key-fingerprint " + key_fingerprint(key) in line
    with pytest.raises(ValueError):
        restricted_key(
            public_key=key + "\n" + key,
            executable=Path("/usr/bin/aptl"),
            binding=Path("/srv/binding.json"),
            grant_id="red-1",
        )


def test_preparation_refuses_partial_or_noncanonical_workload_inventory():
    from types import SimpleNamespace

    from aptl.workbench.preparation import verify_full_inventory

    matrix = SimpleNamespace(
        service_aliases={
            "kali": frozenset({"kali", "aptl-kali"}),
            "misp": frozenset({"misp", "aptl-misp"}),
        }
    )
    with pytest.raises(ValueError):
        verify_full_inventory(matrix, {"aptl-kali": "a" * 64})
    verify_full_inventory(matrix, {"aptl-kali": "a" * 64, "aptl-misp": "b" * 64})
