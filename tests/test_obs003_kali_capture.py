"""Integration tests for OBS-003 Kali-side behavioural capture (ADR-033).

Gated behind ``APTL_SMOKE=1`` (same as the existing
``test_range_integration.py``) so unit-test runs are not slowed down
by a docker-exec round trip. Requires the lab to be running with the
``kali`` profile; auditd checks additionally require the container
to have been granted ``AUDIT_CONTROL`` / ``AUDIT_WRITE`` capabilities
per the OBS-003 docker-compose changes.

Layered ``skipif`` checks: if the kali container isn't up at all,
the whole module is skipped; individual assertions degrade further
if specific capability is unavailable (e.g. auditd refused to start
because the container's runtime doesn't grant audit caps).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests.helpers import (
    LIVE_LAB,
    container_running,
    kali_capture_exec,
    kali_exec,
)

# ---------------------------------------------------------------------------
# Helper: load docker-compose.yml once for compose-consistency tests
# ---------------------------------------------------------------------------
_COMPOSE_PATH = Path(__file__).parent.parent / "docker-compose.yml"


def _load_compose() -> dict:
    with _COMPOSE_PATH.open() as fh:
        return yaml.safe_load(fh)

pytestmark = [
    LIVE_LAB,
    pytest.mark.skipif(
        not container_running("aptl-kali"),
        reason="aptl-kali container is not running",
    ),
]


class TestNonContaminationRemovals:
    """ADR-033: every red→SIEM pipe is gone."""

    def test_no_wazuh_agent_package_installed(self):
        # The pre-installed wazuh-agent package was removed from the
        # Kali image. `dpkg -l wazuh-agent` returns non-zero when the
        # package is not installed.
        r = kali_exec("dpkg -l wazuh-agent 2>/dev/null | grep -E '^ii' || true")
        assert "wazuh-agent" not in r.stdout, (
            "wazuh-agent should not be installed on Kali after ADR-033"
        )

    def test_no_wazuh_processes_running(self):
        r = kali_exec("ps -ef | grep -E 'wazuh|ossec' | grep -v grep || true")
        assert r.stdout.strip() == "", (
            f"Wazuh processes should not be running on Kali; got: {r.stdout}"
        )

    def test_no_rsyslog_forward_config(self):
        # entrypoint.sh's old `*.* @$SIEM_IP:514` forward block was
        # removed. The 90-forward.conf file should not exist.
        r = kali_exec("test -e /etc/rsyslog.d/90-forward.conf && echo yes || echo no")
        assert r.stdout.strip() == "no", (
            "/etc/rsyslog.d/90-forward.conf should not exist after ADR-033"
        )

    def test_no_redteam_logging_helper(self):
        r = kali_exec("test -e /home/kali/redteam_logging.sh && echo yes || echo no")
        assert r.stdout.strip() == "no", (
            "/home/kali/redteam_logging.sh should not exist after ADR-033"
        )

    def test_no_siem_ip_env_var(self):
        # docker-compose no longer sets SIEM_IP on the kali service.
        r = kali_exec("printenv SIEM_IP 2>/dev/null || true")
        assert r.stdout.strip() == "", (
            f"SIEM_IP env var should not be set on Kali; got: {r.stdout!r}"
        )


class TestCaptureSurface:
    """ADR-033: behavioural capture tooling is present and usable."""

    @pytest.mark.parametrize("tool", ["auditd", "accton", "tcpdump", "script"])
    def test_capture_tools_installed(self, tool: str):
        r = kali_exec(f"command -v {tool} >/dev/null && echo ok || echo missing")
        assert r.stdout.strip() == "ok", f"{tool} should be installed on Kali"

    def test_audit_rules_file_present(self):
        r = kali_exec("test -f /etc/audit/rules.d/aptl.rules && echo ok || echo missing")
        assert r.stdout.strip() == "ok", "/etc/audit/rules.d/aptl.rules should be present"

    def test_aptl_wrap_shell_installed_root_owned(self):
        # The wrapper is installed under /usr/local/bin to keep it
        # outside the agent's home (defence in depth — a kali shell
        # escape should not trivially overwrite the capture wiring).
        # Verifies BOTH ownership AND executable mode (test-quality
        # cycle 2 finding-5 — a missing chmod +x in the Dockerfile
        # would silently break the ForceCommand-driven capture and
        # the previous owner-only check could not detect it).
        r = kali_exec(
            "stat -c '%U %a' /usr/local/bin/aptl-wrap-shell.sh 2>/dev/null || echo missing"
        )
        parts = r.stdout.strip().split()
        assert len(parts) == 2, (
            f"Unexpected stat output for /usr/local/bin/aptl-wrap-shell.sh: {r.stdout!r}"
        )
        owner, mode = parts
        assert owner == "root", (
            f"/usr/local/bin/aptl-wrap-shell.sh should be root-owned; got owner: {owner!r}"
        )
        # Owner-execute bit (4xx) must be set so sshd's ForceCommand
        # can spawn it. Accept any 0700-or-wider exec mode.
        owner_mode = int(mode[-3]) if len(mode) >= 3 else 0
        assert owner_mode & 1, (
            f"/usr/local/bin/aptl-wrap-shell.sh missing owner-execute bit; mode {mode!r}"
        )

    def test_sshd_config_accepts_aptl_env_vars(self):
        # AcceptEnv is what lets the MCP server's SendEnv land in the
        # shell. Without it, sshd silently drops the env vars. All
        # three OBS-003 env vars must be listed (test-quality cycle 2
        # finding-4 — dropping APTL_RUN_ID or APTL_TRACE_ID breaks
        # per-run capture routing on the Kali side, but the prior
        # single-var check could not detect it).
        r = kali_exec("grep -E '^AcceptEnv.*APTL_' /etc/ssh/sshd_config || true")
        for var in ("APTL_SESSION_ID", "APTL_RUN_ID", "APTL_TRACE_ID"):
            assert var in r.stdout, (
                f"sshd_config AcceptEnv must include {var}; got: {r.stdout!r}"
            )

    def test_sshd_force_command_set_for_kali(self):
        r = kali_exec(
            "grep -A1 '^Match User kali' /etc/ssh/sshd_config | grep ForceCommand || true"
        )
        assert "aptl-wrap-shell" in r.stdout, (
            "sshd_config Match User kali should ForceCommand the OBS-003 wrapper"
        )

    def test_capture_volume_readonly_in_kali(self):
        # ADR-041 / issue #305: kali_captures is mounted read-only in the
        # kali container so the kali user (including after `sudo su -`)
        # cannot delete or modify capture evidence. A write attempt must
        # fail regardless of Unix ownership or ACLs.
        r = kali_exec(
            "touch /var/log/aptl/captures/_probe 2>&1; echo EXIT=$?"
        )
        assert "EXIT=0" not in r.stdout, (
            "/var/log/aptl/captures must be read-only in the kali container "
            "(ADR-041); touch succeeded when it should have been blocked"
        )

    def test_audit_control_cap_dropped_for_sshd(self):
        # ADR-033 / codex finding-12: sshd is spawned via
        # `capsh --drop=cap_audit_control` so the kali user (who has
        # passwordless sudo) cannot run `sudo auditctl -D` to erase
        # the audit trail mid-scenario. Verify the sshd master
        # process's bounding set does NOT include cap_audit_control.
        sshd_pid = kali_exec("pgrep -f '/usr/sbin/sshd' | head -1").stdout.strip()
        if not sshd_pid:
            pytest.skip("sshd not running yet")
        r = kali_exec(f"grep CapBnd /proc/{sshd_pid}/status").stdout
        # Decode the bounding-set hex mask and check bit 38 (CAP_AUDIT_CONTROL).
        # Bit 30 is CAP_AUDIT_WRITE (must STAY set so loaded rules
        # keep generating events). Format: "CapBnd:	00000000a82400a5"
        line = [l for l in r.splitlines() if "CapBnd" in l][0]
        cap_hex = line.split()[1]
        cap_mask = int(cap_hex, 16)
        # CAP_AUDIT_CONTROL = 30 (not 38 — confused myself above).
        # Reference: <linux/capability.h>.
        assert not (cap_mask & (1 << 30)), (
            f"sshd CapBnd ({cap_hex}) must NOT include CAP_AUDIT_CONTROL "
            "after ADR-033 — kali user with sudo could otherwise erase audit"
        )


class TestEndToEndCapture:
    """End-to-end: actually open an SSH session and verify the
    expected per-session capture artifacts land on the kali side
    (codex pre-push cycle 1 finding-9 — installation-presence tests
    are insufficient; produce real captures and verify them).
    """

    SSH_KEY = "keys/aptl_lab_key"
    SSH_USER = "kali"

    def _kali_ssh_endpoint(self) -> tuple[str, int]:
        """Resolve the host-reachable Kali SSH endpoint.

        Prefer the loopback-only published port used by mcp-red. Older
        native-Linux labs may not have that port yet, so keep the bridge-IP
        fallback for compatibility with already-running developer labs.
        """
        import subprocess as sp

        port = sp.run(
            ["docker", "port", "aptl-kali", "22/tcp"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in port.stdout.splitlines():
            if line.endswith(":2023"):
                return ("localhost", 2023)

        r = sp.run(
            [
                "docker",
                "inspect",
                "aptl-kali",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}\n{{end}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ips = sorted(ip for ip in r.stdout.split() if ip)
        if not ips:
            pytest.skip("could not resolve aptl-kali container IP")
        return (ips[0], 22)

    def _ssh_with_env(self, run_id: str, session_id: str, command: str) -> str:
        """SSH into kali with APTL_* env vars and return stdout."""
        import shutil
        import subprocess as sp
        from pathlib import Path

        if not Path(self.SSH_KEY).exists():
            pytest.skip(f"SSH key {self.SSH_KEY} not present")
        if not shutil.which("ssh"):
            pytest.skip("ssh client not installed")
        host, port = self._kali_ssh_endpoint()
        argv = [
            "ssh",
            "-i",
            self.SSH_KEY,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "SendEnv=APTL_SESSION_ID APTL_RUN_ID APTL_TRACE_ID",
            "-p",
            str(port),
            f"{self.SSH_USER}@{host}",
            command,
        ]
        env = {
            "APTL_SESSION_ID": session_id,
            "APTL_RUN_ID": run_id,
            "APTL_TRACE_ID": run_id,
            # Pass through PATH so ssh client can run.
            "PATH": "/usr/bin:/bin:/usr/local/bin",
        }
        result = sp.run(argv, capture_output=True, text=True, timeout=30, env=env)
        return result.stdout

    def test_session_captures_pty_typescript_and_pcap(self):
        import uuid as _uuid

        run_id = f"e2etest-{_uuid.uuid4().hex[:16]}"
        session_id = f"sess-{_uuid.uuid4().hex[:8]}"
        marker = f"OBS003_MARKER_{_uuid.uuid4().hex[:8]}"

        # Run a command through the wrapped shell.
        self._ssh_with_env(run_id, session_id, f"echo {marker}")

        # ADR-041: captures land in the SIDECAR, which owns the volume — they
        # are NOT visible in the kali workload container at all.
        sess_path = f"/var/log/aptl/captures/{run_id}/{session_id}"
        r = kali_capture_exec(f"test -d {sess_path}/pty && echo ok || echo missing")
        assert r.stdout.strip() == "ok", (
            f"PTY dir missing under {sess_path} in the capture sidecar"
        )

        ts = kali_capture_exec(
            f"cat {sess_path}/pty/typescript 2>/dev/null || true"
        ).stdout
        assert marker in ts, (
            f"PTY typescript at {sess_path}/pty/typescript should contain "
            f"{marker!r}; got {ts!r}"
        )

        # Confirm a pcap was started (presence; rotated file naming depends on
        # tcpdump's -C behaviour, so check the dir in the sidecar).
        r = kali_capture_exec(f"ls {sess_path}/pcap 2>/dev/null | head -1").stdout.strip()
        assert r, f"pcap directory under {sess_path}/pcap should be non-empty"

        # The captures must NOT be reachable from inside the kali workload —
        # not even with sudo (the volume is not mounted there at all).
        r = kali_exec(f"sudo ls {sess_path} 2>&1; echo EXIT=$?")
        assert "EXIT=0" not in r.stdout, (
            f"capture path {sess_path} must not be readable inside aptl-kali "
            f"(ADR-041 read-isolation); got: {r.stdout!r}"
        )

    def test_session_dir_permissions_are_restrictive(self):
        import uuid as _uuid

        run_id = f"e2etest-{_uuid.uuid4().hex[:16]}"
        session_id = f"sess-{_uuid.uuid4().hex[:8]}"

        self._ssh_with_env(run_id, session_id, "true")

        # 0700 dirs, 0600 files inside the per-session subtree (checked in the
        # sidecar, which owns the volume — ADR-041).
        sess_path = f"/var/log/aptl/captures/{run_id}/{session_id}"
        modes = kali_capture_exec(
            f"find {sess_path} -mindepth 1 -printf '%m %p\\n' 2>/dev/null | head -20"
        ).stdout
        # Pre-condition: without this, a silently-failed SSH session (or a
        # wrapper that created no files) leaves `modes` empty, the loop
        # below never executes, and the test passes having asserted
        # nothing about permissions. Mirrors the precondition pattern in
        # test_session_captures_pty_typescript_and_pcap.
        assert modes.strip(), (
            f"No capture artifacts found under {sess_path}; the SSH session "
            "may have failed or the wrapper produced no files — permission "
            "assertions would otherwise be silently skipped"
        )
        for line in modes.splitlines():
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            mode, path = parts
            r = kali_capture_exec(
                f"test -d {path} && echo dir || echo file"
            ).stdout.strip()
            if r == "dir":
                assert mode in ("700", "0700"), f"{path} dir mode {mode}, expected 0700"
            else:
                assert mode in ("600", "0600"), f"{path} file mode {mode}, expected 0600"


class TestProcessLifecycle:
    """Issue #293 / ADR-033 §2: PID 1 must reap children, and the
    container's readiness surface must reflect a completed boot rather
    than masking a failed boot-time child behind an open port 22."""

    def test_pid1_is_an_init_reaper(self):
        # `init: true` on the kali service makes Docker inject its
        # bundled init (docker-init, a tini build) as PID 1. The
        # entrypoint's terminal `exec sleep infinity` is then a child
        # of that init — never PID 1 itself — so orphaned children get
        # reaped instead of zombifying (issue #293).
        comm = kali_exec("cat /proc/1/comm 2>/dev/null || true").stdout.strip()
        assert comm in ("docker-init", "tini"), (
            f"PID 1 should be an init/reaper (docker-init / tini) via "
            f"`init: true`; got {comm!r}. A bare `sleep` as PID 1 cannot "
            "reap orphaned children."
        )

    def test_no_zombie_processes_present(self):
        # The reaping defect surfaced in issue #293 as a `<defunct>`
        # process. With a real init as PID 1 there should be no
        # un-reaped zombies in the container's process table.
        count = kali_exec(
            "ps -eo stat= 2>/dev/null | grep -c '^Z' || true"
        ).stdout.strip()
        assert count == "0", (
            f"container process table has {count} zombie process(es); "
            "PID 1 is not reaping children"
        )

    def test_boot_readiness_marker_present_and_well_formed(self):
        # The entrypoint writes /run/aptl-kali-ready only after every
        # boot step; its presence proves a complete boot. Each capture
        # subsystem records ok|degraded.
        marker = kali_exec(
            "cat /run/aptl-kali-ready 2>/dev/null || true"
        ).stdout
        assert marker.strip(), (
            "/run/aptl-kali-ready is absent — the entrypoint did not "
            "complete boot (the hidden-failure mode of issue #293)"
        )
        keys = dict(
            line.split("=", 1)
            for line in marker.splitlines()
            if "=" in line
        )
        # ADR-041: auditd / process accounting moved to the kali-capture
        # sidecar, so the kali readiness marker only tracks sshd + wrapper.
        for required in ("ready_at", "sshd", "wrapper"):
            assert required in keys, (
                f"readiness marker missing `{required}`; got keys {sorted(keys)}"
            )
        for subsystem in ("sshd", "wrapper"):
            assert keys[subsystem] in ("ok", "degraded"), (
                f"readiness marker `{subsystem}` should be ok|degraded; "
                f"got {keys[subsystem]!r}"
            )
        # The capture subsystems must NOT be reported here anymore — they
        # belong to the sidecar's own readiness marker.
        assert "auditd" not in keys and "procacct" not in keys, (
            "kali readiness marker must not report auditd/procacct after "
            f"ADR-041 (those moved to the sidecar); got keys {sorted(keys)}"
        )
        # sshd and the ForceCommand wrapper are the usable surface —
        # in a healthy lab they must not be degraded.
        assert keys["sshd"] == "ok", "sshd recorded degraded in readiness marker"
        assert keys["wrapper"] == "ok", (
            "OBS-003 ForceCommand wrapper recorded degraded in readiness marker"
        )

    def test_healthcheck_script_installed_root_owned_executable(self):
        # aptl-healthcheck.sh lives under /usr/local/bin (outside the
        # kali user's home) and must be root-owned + executable so the
        # docker healthcheck can run it.
        r = kali_exec(
            "stat -c '%U %a' /usr/local/bin/aptl-healthcheck.sh 2>/dev/null "
            "|| echo missing"
        )
        parts = r.stdout.strip().split()
        assert len(parts) == 2, (
            f"aptl-healthcheck.sh not installed; stat output: {r.stdout!r}"
        )
        owner, mode = parts
        assert owner == "root", f"aptl-healthcheck.sh should be root-owned; got {owner!r}"
        owner_mode = int(mode[-3]) if len(mode) >= 3 else 0
        assert owner_mode & 1, (
            f"aptl-healthcheck.sh missing owner-execute bit; mode {mode!r}"
        )

    def test_healthcheck_passes_on_healthy_container(self):
        # Running the healthcheck against an up, healthy container must
        # exit 0 and report healthy — the script is what docker-compose
        # wires as the kali healthcheck.
        r = kali_exec("/usr/local/bin/aptl-healthcheck.sh; echo EXIT=$?")
        assert "EXIT=0" in r.stdout, (
            f"aptl-healthcheck.sh should pass on a healthy container; "
            f"output: {r.stdout!r} stderr: {r.stderr!r}"
        )
        assert "healthy" in r.stdout, (
            f"aptl-healthcheck.sh should report healthy; got {r.stdout!r}"
        )


# TestComposeConsistency lives in tests/test_kali_capture_compose.py to avoid
# inheriting the module-level LIVE_LAB + kali skipif pytestmark (class-level
# pytestmark in pytest adds to — not replaces — module-level marks).

# ---------------------------------------------------------------------------
# ADR-041 / issue #305: live ownership boundary tests (LIVE_LAB only)
# ---------------------------------------------------------------------------


class TestSidecarOwnershipBoundary:
    """Live tests that verify the kali workload cannot read, list, delete, or
    modify capture evidence even after `sudo su -`. The capture sink is not in
    the kali container's mount namespace at all (ADR-041), so a sudo-capable
    agent has no path to it. Requires APTL_SMOKE=1 and both containers running.
    """

    pytestmark = [
        LIVE_LAB,
        pytest.mark.skipif(
            not container_running("aptl-kali"),
            reason="aptl-kali container is not running",
        ),
    ]

    def test_captures_not_mounted_in_kali(self):
        """The captures volume must be absent from the kali mount table."""
        r = kali_exec(
            "grep -F '/var/log/aptl/captures' /proc/self/mounts || echo NONE"
        )
        assert r.stdout.strip() == "NONE", (
            "kali_captures must NOT be mounted in aptl-kali (ADR-041); "
            f"found mount: {r.stdout!r}"
        )

    def test_sudo_cannot_write_captures_path(self):
        """Even `sudo` cannot create files under the capture path in kali —
        the path is not a writable mount here."""
        r = kali_exec(
            "sudo mkdir -p /var/log/aptl/captures 2>/dev/null; "
            "sudo touch /var/log/aptl/captures/_probe 2>&1; echo EXIT=$?; "
            "sudo rm -f /var/log/aptl/captures/_probe 2>/dev/null || true"
        )
        # The captures dir is owned by the sidecar; in kali it is at most an
        # empty stub on the container's own overlay fs (not the named volume),
        # so even if a write 'succeeds' it never touches real evidence. Assert
        # the sidecar's evidence is unaffected below.
        sidecar = kali_capture_exec(
            "test -e /var/log/aptl/captures/_probe && echo LEAKED || echo SAFE"
        )
        assert sidecar.stdout.strip() == "SAFE", (
            "a kali-side write must never reach the sidecar-owned captures "
            f"volume (ADR-041); kali output: {r.stdout!r}"
        )

    def test_sudo_rm_cannot_delete_sidecar_captures(self):
        """A sudo rm -rf attempt in kali must not destroy sidecar evidence."""
        # Seed an audit log in the sidecar (the entrypoint already does this on
        # boot; assert it exists, then attempt destruction from kali).
        before = kali_capture_exec(
            "test -f /var/log/aptl/captures/_audit/audit.log && echo ok || echo missing"
        ).stdout.strip()
        if before != "ok":
            pytest.skip("sidecar audit log not present (auditd may be degraded)")
        kali_exec("sudo rm -rf /var/log/aptl/captures/* 2>/dev/null || true")
        after = kali_capture_exec(
            "test -f /var/log/aptl/captures/_audit/audit.log && echo ok || echo missing"
        ).stdout.strip()
        assert after == "ok", (
            "sidecar audit evidence was destroyed by a kali-side sudo rm -rf "
            "(ADR-041 acceptance criterion #2)"
        )

    def test_cross_session_read_isolation(self):
        """A kali shell (even sudo) cannot READ another session's captures.

        This is issue #305's cross-session-disclosure criterion: with the
        volume entirely outside kali's mount namespace, there is no path for a
        sudo-root shell to cat a sibling session's typescript/pcap.
        """
        import uuid

        run_id = f"iso-{uuid.uuid4().hex[:8]}"
        session_v = f"sess-victim-{uuid.uuid4().hex[:6]}"
        marker = f"SECRET_{uuid.uuid4().hex[:8]}"

        # Produce a victim session's capture via the wrapped shell.
        TestEndToEndCapture()._ssh_with_env(run_id, session_v, f"echo {marker}")

        victim_ts = f"/var/log/aptl/captures/{run_id}/{session_v}/pty/typescript"
        # Sanity: the sidecar has it.
        s = kali_capture_exec(f"cat {victim_ts} 2>/dev/null || true").stdout
        if marker not in s:
            pytest.skip("victim capture not produced; cannot assert isolation")

        # An authenticated kali shell, even with sudo, must not be able to read
        # it — the path does not exist in kali's mount namespace.
        r = kali_exec(f"sudo cat {victim_ts} 2>&1; echo EXIT=$?")
        assert marker not in r.stdout, (
            f"kali read a sibling session's capture ({victim_ts}); "
            f"cross-session disclosure not closed (ADR-041 / #305): {r.stdout!r}"
        )
        assert "EXIT=0" not in r.stdout, (
            "sudo cat of a sibling session's capture should fail in kali"
        )
