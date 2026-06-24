"""Compose consistency tests for the ADR-041 Kali capture sidecar boundary.

These tests parse docker-compose.yml directly and do NOT require a running
lab (no APTL_SMOKE / LIVE_LAB gate).  They run in every CI unit-test pass.

Issue #305 / ADR-041.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helper: load docker-compose.yml once for compose-consistency tests
# ---------------------------------------------------------------------------
_COMPOSE_PATH = Path(__file__).parent.parent / "docker-compose.yml"


def _load_compose() -> dict:
    with _COMPOSE_PATH.open() as fh:
        return yaml.safe_load(fh)


class TestComposeConsistency:
    """Static assertions about docker-compose.yml that pin the ADR-041 boundary."""

    def test_kali_has_no_captures_mount(self):
        """kali service must NOT mount kali_captures at all (ADR-041).

        A read-only mount would still let a sudo-capable agent READ sibling
        sessions' evidence (ro blocks writes, not reads). The only way to deny
        read/list/modify to a sudo-root shell is to keep the capture sink out
        of the workload container's mount namespace entirely — the sidecar
        owns it and harvest runs against the sidecar.
        """
        compose = _load_compose()
        kali_volumes = compose["services"]["kali"].get("volumes", [])
        # Catch BOTH short-form ("kali_captures:/path[:ro]") and long-form
        # ({type: volume, source: kali_captures, ...}) entries — a dict-form
        # mount would otherwise slip past a str-only filter and re-expose the
        # volume to a sudo-capable agent (test-quality review cycle 1).
        captures_entries = [
            v for v in kali_volumes
            if (isinstance(v, str) and "kali_captures" in v)
            or (isinstance(v, dict) and v.get("source") == "kali_captures")
        ]
        assert not captures_entries, (
            "kali service must NOT mount kali_captures (ADR-041 read-isolation); "
            f"found: {captures_entries!r}"
        )

    def test_kali_capture_service_mounts_captures_rw(self):
        """kali-capture sidecar must mount kali_captures read-write (no :ro)."""
        compose = _load_compose()
        services = compose.get("services", {})
        assert "kali-capture" in services, (
            "kali-capture service must exist in docker-compose.yml (ADR-041)"
        )
        sidecar_volumes = services["kali-capture"].get("volumes", [])
        str_entries = [
            v for v in sidecar_volumes
            if isinstance(v, str) and "kali_captures" in v
        ]
        dict_entries = [
            v for v in sidecar_volumes
            if isinstance(v, dict) and v.get("source") == "kali_captures"
        ]
        assert str_entries or dict_entries, (
            "kali-capture service must have a kali_captures volume entry"
        )
        for entry in str_entries:
            assert not entry.endswith(":ro"), (
                f"kali_captures must NOT be :ro in kali-capture sidecar; got: {entry!r}"
            )
        for entry in dict_entries:
            assert not entry.get("read_only"), (
                f"kali_captures must NOT be read_only in kali-capture sidecar; got: {entry!r}"
            )

    def test_audit_caps_removed_from_kali(self):
        """AUDIT_CONTROL, AUDIT_WRITE, SYS_PACCT must NOT be in kali.cap_add."""
        compose = _load_compose()
        kali_caps = compose["services"]["kali"].get("cap_add", [])
        for cap in ("AUDIT_CONTROL", "AUDIT_WRITE", "SYS_PACCT"):
            assert cap not in kali_caps, (
                f"{cap} must be removed from kali service cap_add (ADR-041); "
                f"these caps belong to the kali-capture sidecar only"
            )

    def test_audit_caps_present_on_sidecar(self):
        """AUDIT_CONTROL, AUDIT_WRITE, SYS_PACCT must be in kali-capture.cap_add."""
        compose = _load_compose()
        services = compose.get("services", {})
        assert "kali-capture" in services, (
            "kali-capture service must exist in docker-compose.yml"
        )
        sidecar_caps = services["kali-capture"].get("cap_add", [])
        for cap in ("AUDIT_CONTROL", "AUDIT_WRITE", "SYS_PACCT"):
            assert cap in sidecar_caps, (
                f"{cap} must be in kali-capture sidecar cap_add (ADR-041)"
            )

    def test_sidecar_no_host_ports(self):
        """kali-capture sidecar must publish no host ports."""
        compose = _load_compose()
        services = compose.get("services", {})
        assert "kali-capture" in services, (
            "kali-capture service must exist in docker-compose.yml"
        )
        ports = services["kali-capture"].get("ports", [])
        assert not ports, (
            f"kali-capture sidecar must have no host ports (ADR-041 auth surface); "
            f"got: {ports}"
        )

    def test_sidecar_in_kali_profile(self):
        """kali-capture must be in the kali profile."""
        compose = _load_compose()
        services = compose.get("services", {})
        assert "kali-capture" in services, (
            "kali-capture service must exist in docker-compose.yml"
        )
        profiles = services["kali-capture"].get("profiles", [])
        assert "kali" in profiles, (
            f"kali-capture sidecar must have profiles: [kali]; got: {profiles}"
        )

    def test_sidecar_has_net_raw(self):
        """kali-capture needs NET_RAW to run tcpdump in the shared netns."""
        compose = _load_compose()
        sidecar_caps = compose["services"]["kali-capture"].get("cap_add", [])
        assert "NET_RAW" in sidecar_caps, (
            "kali-capture sidecar must have NET_RAW for per-session tcpdump "
            f"(ADR-041); got: {sidecar_caps}"
        )

    def test_sidecar_shares_only_network_namespace(self):
        """kali-capture shares Kali's NETWORK namespace but NOT its PID namespace.

        A shared PID namespace would let a sudo-root Kali shell traverse
        `/proc/<sidecar-pid>/root/var/log/aptl/captures` into the sidecar's
        mount namespace and read/delete evidence (codex F2). tcpdump needs only
        the network namespace; auditd/accton are kernel-wide.
        """
        compose = _load_compose()
        sidecar = compose["services"]["kali-capture"]
        assert sidecar.get("network_mode") == "service:kali", (
            f"kali-capture must use network_mode service:kali; got: "
            f"{sidecar.get('network_mode')!r}"
        )
        assert "pid" not in sidecar, (
            "kali-capture must NOT share Kali's PID namespace — it opens a "
            f"/proc/<pid>/root traversal to the capture volume (codex F2); "
            f"got pid: {sidecar.get('pid')!r}"
        )

    def test_sidecar_has_no_hostname(self):
        """`hostname` conflicts with `network_mode: service:` at `up` time.

        Docker rejects the combination when creating the container, so a stray
        hostname here would break a clean `aptl lab start`.
        """
        compose = _load_compose()
        sidecar = compose["services"]["kali-capture"]
        assert "hostname" not in sidecar, (
            "kali-capture must not set hostname — it conflicts with "
            "network_mode: service:kali and fails at container create"
        )
