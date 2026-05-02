"""Verify Wazuh active-response wiring + carve-outs (issue #249).

Pre-#249 the manager declared seven `<command>` blocks but only one
`<active-response>` block (rule 5763 SSH brute-force → bare `firewall-
drop`, 600s, enabled). Every other detection rule fired and nothing
happened. The framework was present but inert.

After #249, the manager:
  - Adds an `<aptl-firewall-drop>` `<command>` that wraps the upstream
    `firewall-drop` and consults a kali-IP whitelist.
  - Adds `<active-response>` blocks for representative high-severity
    rules (webapp / AD / database).
  - Ships every `<active-response>` block with `<disabled>yes</disabled>`,
    `<timeout>` between 60 and 300, and `<level>` >= 10. Blue removes
    the disabled tag per iteration.
  - Bind-mounts a flat-file whitelist at /var/ossec/etc/lists/active-
    response-whitelist with kali's three lab IPs preloaded.
  - Installs the wrapper script at /var/ossec/active-response/bin/aptl-
    firewall-drop on every Wazuh agent in the lab.

These are integration tests gated by `APTL_SMOKE=1`. CI without the lab
skips the file cleanly.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import textwrap
from pathlib import Path

import pytest

from tests.helpers import (
    LIVE_LAB,
    docker_exec,
)

# The three kali-side IPs (kali multi-homed across redteam, dmz, internal).
# All three must be in the whitelist file so AR refuses to drop kali on
# any interface it might present.
KALI_IPS: tuple[str, ...] = ("172.20.4.30", "172.20.1.30", "172.20.2.35")

# Containers running an in-process Wazuh agent (per #248).
IN_PROCESS_TARGETS: tuple[str, ...] = (
    "aptl-webapp",
    "aptl-fileshare",
    "aptl-ad",
    "aptl-dns",
)

# Sidecar agents that also receive the wrapper + whitelist at image
# build time (db and suricata are the carve-outs from #248).
SIDECAR_AGENTS: tuple[str, ...] = (
    "aptl-wazuh-sidecar-db",
    "aptl-wazuh-sidecar-suricata",
)

# Every Wazuh agent in the lab — used for "the AR contract is honored
# everywhere" assertions. The wrapper script and whitelist file ship
# on each.
ALL_AGENTS: tuple[str, ...] = IN_PROCESS_TARGETS + SIDECAR_AGENTS

WAZUH_MANAGER = "aptl-wazuh-manager"
WHITELIST_PATH = "/var/ossec/etc/lists/active-response-whitelist"
WRAPPER_PATH = "/var/ossec/active-response/bin/aptl-firewall-drop"
MANAGER_OSSEC = "/var/ossec/etc/ossec.conf"

# Repo paths for source-level tests that don't require the lab to be
# up. These let CI catch regressions in the source files without
# spinning up Docker.
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_MANAGER_CONF = REPO_ROOT / "config" / "wazuh_cluster" / "wazuh_manager.conf"
SRC_WHITELIST = REPO_ROOT / "config" / "wazuh_cluster" / "etc" / "lists" / "active-response-whitelist"
SRC_WRAPPER = REPO_ROOT / "containers" / "_wazuh-agent" / "aptl-firewall-drop.sh"
SRC_INSTALL = REPO_ROOT / "containers" / "_wazuh-agent" / "install.sh"

# Dockerfiles that must each install the wrapper + whitelist via the
# install.sh /tmp pre-COPY pattern.
AGENT_DOCKERFILES: tuple[Path, ...] = (
    REPO_ROOT / "containers" / "webapp" / "Dockerfile",
    REPO_ROOT / "containers" / "fileshare" / "Dockerfile",
    REPO_ROOT / "containers" / "ad" / "Dockerfile",
    REPO_ROOT / "containers" / "dns" / "Dockerfile",
    REPO_ROOT / "containers" / "wazuh-sidecar" / "Dockerfile",
)


def _container_running(name: str) -> bool:
    """Return True if the named container is in `docker ps` output."""
    from tests.helpers import run_cmd

    result = run_cmd(["docker", "ps", "--format", "{{.Names}}"], timeout=10)
    if result.returncode != 0:
        return False
    return name in result.stdout.split()


def _require_lab_up() -> None:
    """Skip the test if the manager OR any agent (in-process or sidecar)
    is missing. These tests exercise live-lab integration; without all
    required containers present, a failure is environmental, not a real
    regression."""
    needed = (WAZUH_MANAGER, *ALL_AGENTS)
    missing = [c for c in needed if not _container_running(c)]
    if missing:
        pytest.skip(
            f"Lab not fully up; missing containers: {missing}. "
            f"Run `aptl lab start` first.",
        )


def _read_manager_ossec() -> str:
    """Read the deployed manager ossec.conf content. Skips if the lab
    or manager is not running."""
    _require_lab_up()
    result = docker_exec(WAZUH_MANAGER, f"cat {MANAGER_OSSEC}")
    if result.returncode != 0:
        pytest.skip(
            f"{WAZUH_MANAGER} not reachable or ossec.conf missing "
            f"(rc={result.returncode}, stderr={result.stderr[:200]})",
        )
    return result.stdout


def _all_active_response_blocks(content: str) -> list[str]:
    """Return every `<active-response>...</active-response>` block as
    raw XML. Naive regex but sufficient for the manager config we own —
    no nested AR blocks exist in Wazuh."""
    return re.findall(
        r"<active-response>.*?</active-response>",
        content,
        re.DOTALL,
    )


@pytest.fixture
def _check_lab_up() -> None:
    """Skip a test when the lab is not up. Applied via
    `@pytest.mark.usefixtures("_check_lab_up")` on live-lab classes
    only (not on TestWazuhActiveResponseSource, which runs without
    Docker)."""
    _require_lab_up()


@LIVE_LAB
@pytest.mark.usefixtures("_check_lab_up")
class TestWazuhActiveResponseConfig:
    """Manager-side AR config: command, AR blocks, and whitelist."""

    def test_aptl_firewall_drop_command_is_declared(self) -> None:
        """The wrapper command must be registered with the manager so
        `<active-response>` blocks can reference it."""
        content = _read_manager_ossec()
        # Must contain a `<command>` block whose `<name>` is exactly
        # `aptl-firewall-drop` and whose `<executable>` is the same.
        m = re.search(
            r"<command>\s*<name>aptl-firewall-drop</name>\s*"
            r"<executable>aptl-firewall-drop</executable>\s*"
            r"<timeout_allowed>yes</timeout_allowed>\s*</command>",
            content,
            re.DOTALL,
        )
        assert m is not None, (
            "Expected `<command><name>aptl-firewall-drop</name>"
            "<executable>aptl-firewall-drop</executable>"
            "<timeout_allowed>yes</timeout_allowed></command>` block in "
            "manager ossec.conf. The manager dispatches AR by command "
            "name; without this registration, every `<active-response>` "
            "block referencing `aptl-firewall-drop` is a no-op."
        )

    def test_active_response_blocks_have_required_carve_outs(self) -> None:
        """Every `<active-response>` block in the manager config must
        ship `<disabled>yes</disabled>`, a finite `<timeout>` between
        60 and 300, and `<level>` >= 10. Together these are the per-
        target carve-outs the issue calls for: starting posture is off
        (blue enables per iter), drops auto-roll-back, and only high-
        severity rules can fire AR."""
        content = _read_manager_ossec()
        blocks = _all_active_response_blocks(content)
        assert len(blocks) >= 3, (
            f"Expected >= 3 `<active-response>` blocks (the rule-5763 "
            f"original plus at least 2 representative new ones). Found "
            f"{len(blocks)}."
        )
        violations: list[str] = []
        for i, block in enumerate(blocks):
            if "<disabled>yes</disabled>" not in block:
                violations.append(
                    f"block #{i}: missing `<disabled>yes</disabled>` (default "
                    f"posture is OFF; blue enables per iteration)",
                )
            timeout_match = re.search(r"<timeout>(\d+)</timeout>", block)
            if not timeout_match:
                violations.append(f"block #{i}: missing `<timeout>` directive")
            else:
                timeout = int(timeout_match.group(1))
                if not (60 <= timeout <= 300):
                    violations.append(
                        f"block #{i}: timeout={timeout}s outside [60, 300] "
                        f"(carve-out: timeout-bounded so drops auto-rollback)",
                    )
            level_match = re.search(r"<level>(\d+)</level>", block)
            if not level_match:
                violations.append(
                    f"block #{i}: missing `<level>` directive (severity gate "
                    f"prevents low-severity alerts from chaining into bans)",
                )
            elif int(level_match.group(1)) < 10:
                violations.append(
                    f"block #{i}: level={level_match.group(1)} < 10 (gate "
                    f"requires level >= 10)",
                )
        assert not violations, (
            "Per-target carve-outs not enforced on every block:\n  "
            + "\n  ".join(violations)
        )

    def test_active_response_uses_wrapper_not_bare_firewall_drop(self) -> None:
        """No `<active-response>` block may reference bare `firewall-
        drop`. Every block must use the `aptl-firewall-drop` wrapper so
        the kali whitelist is consulted at exec time. (Other commands
        like `host-deny` are fine and may appear.)"""
        content = _read_manager_ossec()
        blocks = _all_active_response_blocks(content)
        leaks: list[str] = []
        for i, block in enumerate(blocks):
            cmd_match = re.search(r"<command>([^<]+)</command>", block)
            if not cmd_match:
                continue
            cmd = cmd_match.group(1).strip()
            if cmd == "firewall-drop":
                leaks.append(
                    f"block #{i} uses bare `firewall-drop` instead of "
                    f"`aptl-firewall-drop` — kali whitelist will be "
                    f"bypassed",
                )
        assert not leaks, "AR blocks must use the wrapper:\n  " + "\n  ".join(
            leaks,
        )

@LIVE_LAB
@pytest.mark.usefixtures("_check_lab_up")
class TestWazuhActiveResponseWhitelist:
    """The kali-IP whitelist file is installed on every in-process
    agent and populated with kali's three lab IPs. The wrapper script
    runs on the agent, so the file ships in each agent's image at
    build time."""

    def test_whitelist_file_present_on_every_agent(self) -> None:
        """Whitelist file must exist at the canonical path inside every
        Wazuh agent — both the in-process targets (4) AND the remaining
        sidecars (db, suricata). The wrapper consults it at exec time;
        ADR-021's contract is that the file ships on EVERY agent so
        any AR rule that fires honors the carve-out."""
        missing: list[str] = []
        for target in ALL_AGENTS:
            result = docker_exec(target, f"test -f {WHITELIST_PATH}")
            if result.returncode != 0:
                missing.append(target)
        assert not missing, (
            f"{WHITELIST_PATH} missing inside agents: {missing}. The "
            f"Dockerfile's COPY + install of the whitelist may have "
            f"been removed."
        )

    def test_whitelist_contains_kali_ips(self) -> None:
        """Each of kali's three lab IPs must appear in the whitelist
        on its own line (the wrapper uses `grep -Fxq` to match). Sample
        from one agent — file content is identical across all agents
        because they all COPY the same source file."""
        result = docker_exec("aptl-webapp", f"cat {WHITELIST_PATH}")
        assert result.returncode == 0, (
            f"could not read {WHITELIST_PATH} on aptl-webapp: "
            f"{result.stderr[:200]}"
        )
        # Strip comments and blank lines for the membership check.
        lines = [
            ln.strip()
            for ln in result.stdout.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        missing = [ip for ip in KALI_IPS if ip not in lines]
        assert not missing, (
            f"Kali IPs missing from whitelist: {missing}. Without all "
            f"three present, the wrapper will allow `firewall-drop` to "
            f"fire on the missing kali interface, ending the purple loop."
        )


@LIVE_LAB
@pytest.mark.usefixtures("_check_lab_up")
class TestWazuhActiveResponseWrapper:
    """The wrapper script is installed on every Wazuh agent and behaves
    correctly for both whitelisted and non-whitelisted source IPs."""

    def test_wrapper_installed_on_every_agent(self) -> None:
        """Every Wazuh agent — in-process targets (4) AND sidecars (db,
        suricata) — must have the wrapper at the canonical path with
        execute bit set. The agent's wazuh-execd runs scripts from this
        directory by name; missing on a sidecar means AR fired against
        that agent would bypass the kali whitelist."""
        broken: list[str] = []
        for target in ALL_AGENTS:
            result = docker_exec(target, f"test -x {WRAPPER_PATH}")
            if result.returncode != 0:
                broken.append(
                    f"{target}: {WRAPPER_PATH} missing or not executable "
                    f"(rc={result.returncode})",
                )
        assert not broken, (
            "Wrapper script missing on one or more agents:\n  "
            + "\n  ".join(broken)
        )

    def test_wrapper_skips_whitelisted_srcip(self) -> None:
        """When invoked with a Wazuh AR `add` command and a srcip
        present in the whitelist, the wrapper exits 0 without calling
        the upstream firewall-drop. We mock the upstream by setting
        `APTL_AR_ORIGINAL=/bin/false` — if the wrapper forwards, the
        process exits non-zero. With the whitelist short-circuit, it
        never forwards and exits 0."""
        # Use kali's redteam IP, which must be on the whitelist.
        ar_payload = json.dumps(
            {
                "version": 1,
                "command": "add",
                "parameters": {
                    "extra_args": [],
                    "alert": {"data": {"srcip": KALI_IPS[0]}},
                    "program": "firewall-drop",
                },
            },
        )
        # Run inside aptl-webapp (any in-process target works). Use
        # `printf '%s'` not `echo` for predictable stdin, and rely on
        # docker_exec's `bash -c` as the only shell layer (no nested
        # `sh -c '...'` — the inner quoting collides with the JSON's
        # double quotes).
        cmd = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_ORIGINAL=/bin/false {WRAPPER_PATH}"
        )
        result = docker_exec("aptl-webapp", cmd)
        assert result.returncode == 0, (
            f"Wrapper did not short-circuit for whitelisted srcip "
            f"{KALI_IPS[0]}. rc={result.returncode}, stderr="
            f"{result.stderr[:200]}. With APTL_AR_ORIGINAL=/bin/false, "
            f"a non-zero exit means the wrapper forwarded to /bin/false "
            f"instead of skipping."
        )

    def test_wrapper_forwards_non_whitelisted_srcip(self) -> None:
        """When invoked with a non-whitelisted srcip, the wrapper must
        forward to the upstream. We mock the upstream with /bin/true
        (exits 0 regardless of input) and assert the wrapper exits 0
        — confirming forward semantics. To distinguish from the skip
        path, we then re-run with /bin/false and assert non-zero exit
        (forward picked up the non-zero from the mock upstream)."""
        ar_payload = json.dumps(
            {
                "version": 1,
                "command": "add",
                "parameters": {
                    "extra_args": [],
                    "alert": {"data": {"srcip": "10.99.99.99"}},
                    "program": "firewall-drop",
                },
            },
        )
        cmd_true = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_ORIGINAL=/bin/true {WRAPPER_PATH}"
        )
        result_true = docker_exec("aptl-webapp", cmd_true)
        assert result_true.returncode == 0, (
            f"Wrapper rc={result_true.returncode} when forwarding to "
            f"/bin/true; expected 0. stderr={result_true.stderr[:200]}"
        )

        cmd_false = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_ORIGINAL=/bin/false {WRAPPER_PATH}"
        )
        result_false = docker_exec("aptl-webapp", cmd_false)
        assert result_false.returncode != 0, (
            "Wrapper exited 0 when forwarding to /bin/false; expected "
            "non-zero. The wrapper may have short-circuited (treating "
            "10.99.99.99 as whitelisted) when it should have forwarded."
        )

    def test_wrapper_forwards_delete_command_even_for_whitelisted(self) -> None:
        """The `delete` phase (timeout cleanup) must always forward,
        even for whitelisted IPs. Otherwise a previously-installed drop
        rule (added before the IP joined the whitelist) would never get
        cleaned up. We assert: command="delete" + whitelisted srcip
        still forwards to the upstream."""
        ar_payload = json.dumps(
            {
                "version": 1,
                "command": "delete",
                "parameters": {
                    "extra_args": [],
                    "alert": {"data": {"srcip": KALI_IPS[0]}},
                    "program": "firewall-drop",
                },
            },
        )
        # If the wrapper forwards, it pipes to /bin/false → rc=1.
        # If it short-circuits (wrong behavior on delete), rc=0.
        cmd = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_ORIGINAL=/bin/false {WRAPPER_PATH}"
        )
        result = docker_exec("aptl-webapp", cmd)
        assert result.returncode != 0, (
            "Wrapper short-circuited on `command=delete` for whitelisted "
            "srcip. Cleanup must always forward — otherwise stale drop "
            "rules accumulate."
        )

    def test_wrapper_logs_skip_to_active_responses_log(self) -> None:
        """When the wrapper short-circuits, it must log a `SKIPPED for
        whitelisted <ip>` line to /var/ossec/logs/active-responses.log
        so blue can audit which AR invocations were suppressed by the
        whitelist."""
        sentinel_ip = KALI_IPS[1]  # different IP from skip test for clarity
        ar_payload = json.dumps(
            {
                "version": 1,
                "command": "add",
                "parameters": {
                    "extra_args": [],
                    "alert": {"data": {"srcip": sentinel_ip}},
                    "program": "firewall-drop",
                },
            },
        )
        # Trigger the skip.
        cmd = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_ORIGINAL=/bin/false {WRAPPER_PATH}"
        )
        trigger = docker_exec("aptl-webapp", cmd)
        assert trigger.returncode == 0, (
            f"wrapper failed to short-circuit (rc={trigger.returncode})"
        )
        # Verify log entry.
        log_check = docker_exec(
            "aptl-webapp",
            f"grep -F 'SKIPPED for whitelisted {sentinel_ip}' "
            f"/var/ossec/logs/active-responses.log",
        )
        assert log_check.returncode == 0, (
            f"Wrapper did not log the skip for {sentinel_ip} to "
            f"/var/ossec/logs/active-responses.log. Without an audit "
            f"trail, blue can't tell which AR invocations the whitelist "
            f"suppressed."
        )


# =============================================================================
# Source-level tests — no lab required.
#
# These run in CI without Docker; they parse the repo's source files to
# catch regressions that the live-lab integration tests would miss when
# the lab is down. The wrapper unit-tests use a temp whitelist and a
# /bin/true mock upstream so we exercise the script logic locally.
# =============================================================================


class TestWazuhActiveResponseSource:
    """Source-file integrity. No Docker, no lab — these are pytest's
    floor of safety: if these fail, the next live-lab run won't even
    have a chance of being correct."""

    def test_manager_conf_declares_wrapper_command(self) -> None:
        """The repo's manager config must declare the `aptl-firewall-
        drop` `<command>` block."""
        content = SRC_MANAGER_CONF.read_text()
        assert (
            "<name>aptl-firewall-drop</name>" in content
            and "<executable>aptl-firewall-drop</executable>" in content
        ), (
            "Manager config missing aptl-firewall-drop <command> block. "
            "Without this declaration, the manager has no name to dispatch "
            "for the wrapper, and every <active-response> referencing it "
            "is a no-op."
        )

    def test_manager_conf_active_response_blocks_disabled_by_default(self) -> None:
        """Source-level mirror of test_active_response_blocks_have_required_
        carve_outs — runs without the lab."""
        content = SRC_MANAGER_CONF.read_text()
        blocks = re.findall(
            r"<active-response>.*?</active-response>",
            content,
            re.DOTALL,
        )
        assert len(blocks) >= 3, (
            f"Source manager config has {len(blocks)} <active-response> "
            f"blocks; expected >= 3"
        )
        violations: list[str] = []
        for i, block in enumerate(blocks):
            if "<disabled>yes</disabled>" not in block:
                violations.append(f"block #{i}: not disabled by default")
            if "<level>" not in block:
                violations.append(f"block #{i}: missing <level>")
            if "<timeout>" not in block:
                violations.append(f"block #{i}: missing <timeout>")
        assert not violations, "Carve-outs not enforced in source:\n  " + "\n  ".join(
            violations,
        )

    def test_manager_conf_uses_wrapper_for_firewall_drop_blocks(self) -> None:
        """No <active-response> block in source may reference bare
        `firewall-drop` — every block that wants firewall-drop semantics
        must use the `aptl-firewall-drop` wrapper."""
        content = SRC_MANAGER_CONF.read_text()
        blocks = re.findall(
            r"<active-response>.*?</active-response>",
            content,
            re.DOTALL,
        )
        leaks: list[str] = []
        for i, block in enumerate(blocks):
            cmd = re.search(r"<command>([^<]+)</command>", block)
            if cmd and cmd.group(1).strip() == "firewall-drop":
                leaks.append(
                    f"block #{i}: bare firewall-drop (use aptl-firewall-drop)",
                )
        assert not leaks, "\n  ".join(leaks)

    def test_whitelist_file_format(self) -> None:
        """The repo's whitelist file must contain kali's three IPs as
        bare IPv4 addresses, one per line — `grep -Fxq` semantics
        require whole-line matching with no inline content."""
        content = SRC_WHITELIST.read_text()
        ip_lines = [
            ln.strip()
            for ln in content.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        # Each non-comment line must be a bare IPv4. Inline comments
        # like "172.20.4.30  # kali" would be a silent regression.
        bare_ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        bad = [ln for ln in ip_lines if not bare_ipv4.match(ln)]
        assert not bad, (
            f"Whitelist source file contains non-bare-IPv4 lines: {bad}. "
            f"`grep -Fxq` matches the entire line, so `172.20.4.30  # kali` "
            f"on one line silently fails to match."
        )
        missing = [ip for ip in KALI_IPS if ip not in ip_lines]
        assert not missing, f"Kali IPs missing from source whitelist: {missing}"

    def test_wrapper_script_rejects_invalid_ipv4(self, tmp_path: Path) -> None:
        """The wrapper's IPv4 validation must reject malformed input —
        notably a srcip with an embedded newline + whitelisted IP, which
        without validation would let `grep -Fxq` match the embedded
        line and short-circuit. We exercise the wrapper directly (bash,
        no Docker) with `APTL_AR_ORIGINAL=/bin/false` so any forward
        path exits 1; a short-circuit (rc=0) on an INVALID srcip would
        signal a regression."""
        wl = tmp_path / "whitelist"
        wl.write_text("172.20.4.30\n")
        log = tmp_path / "log"
        # srcip="evil\n172.20.4.30" — the validation must reject the
        # newline; the wrapper must NOT short-circuit.
        payload = json.dumps(
            {
                "command": "add",
                "parameters": {
                    "alert": {"data": {"srcip": "evil\n172.20.4.30"}},
                },
            },
        )
        env = {
            **os.environ,
            "APTL_AR_WHITELIST": str(wl),
            "APTL_AR_ORIGINAL": "/bin/false",
            "APTL_AR_LOG": str(log),
        }
        result = subprocess.run(
            ["bash", str(SRC_WRAPPER)],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert result.returncode != 0, (
            "Wrapper short-circuited on a srcip with an embedded "
            "newline. Without IPv4 validation, an attacker controlling "
            "a Wazuh decoder srcip field could spoof a whitelist hit "
            "by including a real whitelisted IP after a newline."
        )

    def test_wrapper_script_short_circuits_valid_whitelisted(self, tmp_path: Path) -> None:
        """Source-level happy-path: a valid whitelisted IPv4 must short-
        circuit (rc=0 with /bin/false mock means the wrapper didn't
        forward)."""
        wl = tmp_path / "whitelist"
        wl.write_text("172.20.4.30\n")
        log = tmp_path / "log"
        payload = json.dumps(
            {
                "command": "add",
                "parameters": {"alert": {"data": {"srcip": "172.20.4.30"}}},
            },
        )
        env = {
            **os.environ,
            "APTL_AR_WHITELIST": str(wl),
            "APTL_AR_ORIGINAL": "/bin/false",
            "APTL_AR_LOG": str(log),
        }
        result = subprocess.run(
            ["bash", str(SRC_WRAPPER)],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert result.returncode == 0, (
            f"Wrapper failed to short-circuit on whitelisted 172.20.4.30; "
            f"rc={result.returncode}, stderr={result.stderr[:200]}"
        )
        # Log file must contain the SKIPPED entry.
        assert log.exists() and "SKIPPED for whitelisted 172.20.4.30" in log.read_text(), (
            f"Log file missing or no SKIPPED entry; contents: "
            f"{log.read_text() if log.exists() else '<no file>'}"
        )

    def test_wrapper_script_forwards_delete_unconditionally(self, tmp_path: Path) -> None:
        """delete + whitelisted IP must still forward."""
        wl = tmp_path / "whitelist"
        wl.write_text("172.20.4.30\n")
        log = tmp_path / "log"
        payload = json.dumps(
            {
                "command": "delete",
                "parameters": {"alert": {"data": {"srcip": "172.20.4.30"}}},
            },
        )
        env = {
            **os.environ,
            "APTL_AR_WHITELIST": str(wl),
            "APTL_AR_ORIGINAL": "/bin/false",
            "APTL_AR_LOG": str(log),
        }
        result = subprocess.run(
            ["bash", str(SRC_WRAPPER)],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert result.returncode != 0, (
            "Wrapper short-circuited on delete; cleanup must always forward."
        )

    def test_install_script_handles_optional_ar_extras(self) -> None:
        """install.sh must check for /tmp/aptl-firewall-drop.sh and
        /tmp/active-response-whitelist and `install` them with the
        right perms when present. Centralizing the install in install.sh
        is the fix for codex finding #4 (Dockerfile boilerplate
        duplication); a regression here breaks every Dockerfile's
        AR install at build time."""
        content = SRC_INSTALL.read_text()
        assert "/tmp/aptl-firewall-drop.sh" in content, (
            "install.sh missing /tmp/aptl-firewall-drop.sh handling — "
            "Dockerfiles pre-COPY the wrapper to that path expecting "
            "install.sh to install it."
        )
        assert "/tmp/active-response-whitelist" in content, (
            "install.sh missing /tmp/active-response-whitelist handling"
        )
        assert re.search(r"install -D? ?-m 0755 -o root -g wazuh", content), (
            "install.sh wrapper install must set mode 0755 root:wazuh"
        )
        assert re.search(r"install -D? ?-m 0640 -o root -g wazuh", content), (
            "install.sh whitelist install must set mode 0640 root:wazuh"
        )

    def test_every_agent_dockerfile_pre_copies_ar_extras(self) -> None:
        """Every Wazuh-agent-bearing Dockerfile must pre-COPY the
        wrapper + whitelist into /tmp before install.sh runs, then
        rm them in the same RUN. This is the contract that lets the
        centralized install.sh handle the AR-extras step."""
        violations: list[str] = []
        for dockerfile in AGENT_DOCKERFILES:
            text = dockerfile.read_text()
            for required in (
                "containers/_wazuh-agent/aptl-firewall-drop.sh",
                "config/wazuh_cluster/etc/lists/active-response-whitelist",
                "/tmp/aptl-firewall-drop.sh",
                "/tmp/active-response-whitelist",
            ):
                if required not in text:
                    violations.append(
                        f"{dockerfile.relative_to(REPO_ROOT)}: missing reference to '{required}'"
                    )
        assert not violations, (
            "Dockerfile AR-extras contract violated:\n  "
            + "\n  ".join(violations)
        )
