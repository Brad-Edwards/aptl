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
    raw XML. Anchor on a line-start `<active-response>` to avoid
    matching the literal text inside `<!-- ... <active-response> ... -->`
    comments (which our manager config has — the comments describe the
    framework above the actual AR blocks)."""
    return re.findall(
        r"^\s*<active-response>.*?</active-response>",
        content,
        re.DOTALL | re.MULTILINE,
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
        `<active-response>` blocks can reference it. Required directives:
        `<name>` = `aptl-firewall-drop`, `<executable>` = same,
        `<expect>srcip</expect>` (manager skips dispatch when the alert
        doesn't carry srcip), `<timeout_allowed>yes`."""
        content = _read_manager_ossec()
        # Find the <command> block by name; check each required child.
        m = re.search(
            r"<command>(?P<body>.*?</command>)",
            content[content.find("<name>aptl-firewall-drop</name>") - 50:]
                if "<name>aptl-firewall-drop</name>" in content else "",
            re.DOTALL,
        )
        assert "<name>aptl-firewall-drop</name>" in content, (
            "Manager ossec.conf has no <command> block named "
            "aptl-firewall-drop. Without this registration, every "
            "<active-response> block referencing aptl-firewall-drop "
            "is a no-op."
        )
        # Pull the surrounding <command>...</command> block by name match.
        m = re.search(
            r"<command>[^<]*<name>aptl-firewall-drop</name>.*?</command>",
            content,
            re.DOTALL,
        )
        assert m is not None, "could not locate aptl-firewall-drop <command> block"
        block = m.group(0)
        assert "<executable>aptl-firewall-drop</executable>" in block, (
            "aptl-firewall-drop <command> missing matching <executable>"
        )
        assert "<expect>srcip</expect>" in block, (
            "aptl-firewall-drop <command> missing <expect>srcip</expect>; "
            "without this, the manager dispatches AR for alerts that "
            "don't carry srcip and the script no-ops without surfacing "
            "the misfire to the manager."
        )
        assert "<timeout_allowed>yes</timeout_allowed>" in block, (
            "aptl-firewall-drop <command> missing <timeout_allowed>yes</timeout_allowed>"
        )

    def test_active_response_blocks_have_required_carve_outs(self) -> None:
        """Every `<active-response>` block in the manager config must
        ship `<disabled>yes</disabled>` (default OFF), a finite
        `<timeout>` in [60, 300] (auto-rollback), and a specific
        `<rules_id>` (per-rule scoping).

        We deliberately do NOT require `<level>`. Wazuh AR's matchers
        (`<rules_id>`, `<rules_group>`, `<level>`) are OR'd, not AND'd
        — adding `<level>10</level>` to a block that already has
        `<rules_id>` BROADENS the block to fire on every level-10+
        alert. The severity gate is enforced implicitly by selecting
        level-10+ rules in `<rules_id>`."""
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
            if not re.search(r"<rules_id>\d+</rules_id>", block):
                violations.append(
                    f"block #{i}: missing `<rules_id>` (per-rule scoping is "
                    f"the only correct severity-gate pattern in Wazuh AR)",
                )
            # Reject `<level>` next to `<rules_id>` — Wazuh OR's them.
            if "<level>" in block and "<rules_id>" in block:
                violations.append(
                    f"block #{i}: `<level>` AND `<rules_id>` together — "
                    f"Wazuh OR's matchers, broadening the block to every "
                    f"level-N+ alert. Drop the `<level>`.",
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
        present in the whitelist, the wrapper exits 0 without running
        any iptables operation. Mock the iptables binary with
        `APTL_AR_IPTABLES=/bin/false` — if the wrapper invokes
        iptables for an `add`, the process exits non-zero. Whitelist
        short-circuit means it never reaches iptables."""
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
        cmd = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_IPTABLES=/bin/false {WRAPPER_PATH}"
        )
        result = docker_exec("aptl-webapp", cmd)
        assert result.returncode == 0, (
            f"Wrapper did not short-circuit for whitelisted srcip "
            f"{KALI_IPS[0]}. rc={result.returncode}, stderr="
            f"{result.stderr[:200]}"
        )

    def test_wrapper_runs_iptables_for_non_whitelisted_srcip(self) -> None:
        """When invoked with a non-whitelisted srcip on `add`, the
        wrapper must call iptables `-I` (insert). A naive `/bin/true`
        mock makes `iptables -C` succeed (rule "already present") and
        the wrapper short-circuits with a no-op — never exercising the
        insert. Use a smarter mock that returns 1 for `-C` (rule not
        present) and 0 for `-I` (insert succeeded), then assert the
        wrapper logged 'added DROP' for the srcip — proving the
        insert branch ran."""
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
        # Install a fake iptables in /tmp/aptl-fake-iptables that:
        #   -C → exit 1 (rule not present)
        #   -I → exit 0 (insert succeeds)
        #   -D → exit 0
        fake_iptables = "/tmp/aptl-fake-iptables.sh"
        fake_script = textwrap.dedent("""\
            #!/bin/bash
            for arg in "$@"; do
                case "$arg" in
                    -C) exit 1 ;;
                    -I) exit 0 ;;
                    -D) exit 0 ;;
                esac
            done
            exit 0
        """)
        # Write the fake iptables script in a single docker exec —
        # printf then chmod, both inside one bash -c so the file is
        # executable when the wrapper invokes it below.
        write = docker_exec(
            "aptl-webapp",
            f"bash -c {shlex.quote(f'printf %s {shlex.quote(fake_script)} > {fake_iptables} && chmod +x {fake_iptables}')}",
        )
        assert write.returncode == 0, (
            f"could not install fake iptables: rc={write.returncode}, "
            f"stderr={write.stderr[:200]}"
        )

        cmd = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_IPTABLES={fake_iptables} {WRAPPER_PATH}"
        )
        result = docker_exec("aptl-webapp", cmd)
        assert result.returncode == 0, (
            f"Wrapper rc={result.returncode} with smart mock; expected "
            f"0 (insert succeeded). stderr={result.stderr[:200]}"
        )
        # Verify the insert branch actually ran via the audit log.
        log_check = docker_exec(
            "aptl-webapp",
            "grep -F 'added DROP for 10.99.99.99' "
            "/var/ossec/logs/active-responses.log",
        )
        assert log_check.returncode == 0, (
            "Wrapper did not log 'added DROP for 10.99.99.99' — the "
            "insert branch did not run. With the smart mock returning "
            "1 for -C and 0 for -I, the wrapper should have called -I "
            "and logged the addition."
        )

    def test_wrapper_runs_delete_even_for_whitelisted(self) -> None:
        """The `delete` phase (timeout cleanup) must always run iptables
        delete, even for whitelisted IPs — otherwise drops installed
        before an IP joined the whitelist would never be reaped. With
        `/bin/false` mock for iptables, the wrapper's delete path
        attempts `iptables -C` (returns 1, "not present") and exits 0
        — that's correct delete-cleanup behavior."""
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
        # Mock with /bin/false — iptables -C returns 1, the wrapper
        # treats that as "no matching rule to delete" and exits 0.
        # The CRITICAL check: wrapper did NOT short-circuit on the
        # whitelist. We verify by checking the log for a 'removed N
        # DROP rule(s)' line — only present if the delete branch ran.
        cmd = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_IPTABLES=/bin/false {WRAPPER_PATH}"
        )
        result = docker_exec("aptl-webapp", cmd)
        assert result.returncode == 0, (
            f"Wrapper rc={result.returncode} on delete with /bin/false "
            f"mock; expected 0 (no rule to delete is OK). "
            f"stderr={result.stderr[:200]}"
        )
        log_check = docker_exec(
            "aptl-webapp",
            f"grep -F 'removed' /var/ossec/logs/active-responses.log "
            f"| grep -F '{KALI_IPS[0]}'",
        )
        assert log_check.returncode == 0, (
            f"Wrapper short-circuited on `command=delete` for whitelisted "
            f"{KALI_IPS[0]}. The delete branch must always run."
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
        # Trigger the skip. iptables mock /bin/false ensures the wrapper
        # doesn't actually mutate iptables; if the wrapper failed to
        # short-circuit, /bin/false would propagate non-zero.
        cmd = (
            f"printf %s {shlex.quote(ar_payload)} | "
            f"APTL_AR_IPTABLES=/bin/false {WRAPPER_PATH}"
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
        drop` `<command>` block, including `<expect>srcip</expect>` so
        the manager skips dispatch when an alert carries no srcip."""
        content = SRC_MANAGER_CONF.read_text()
        assert "<name>aptl-firewall-drop</name>" in content, (
            "Manager config missing aptl-firewall-drop <command> block."
        )
        m = re.search(
            r"<command>[^<]*<name>aptl-firewall-drop</name>.*?</command>",
            content,
            re.DOTALL,
        )
        assert m is not None, "could not locate aptl-firewall-drop <command> block"
        block = m.group(0)
        assert "<executable>aptl-firewall-drop</executable>" in block, (
            "aptl-firewall-drop <command> missing matching <executable>"
        )
        assert "<expect>srcip</expect>" in block, (
            "aptl-firewall-drop <command> missing <expect>srcip</expect>"
        )

    def test_manager_conf_active_response_blocks_disabled_by_default(self) -> None:
        """Source-level mirror of test_active_response_blocks_have_required_
        carve_outs — runs without the lab. Anchored regex avoids
        matching the `<active-response>` text inside XML comments."""
        content = SRC_MANAGER_CONF.read_text()
        blocks = re.findall(
            r"^\s*<active-response>.*?</active-response>",
            content,
            re.DOTALL | re.MULTILINE,
        )
        assert len(blocks) >= 3, (
            f"Source manager config has {len(blocks)} <active-response> "
            f"blocks; expected >= 3"
        )
        violations: list[str] = []
        for i, block in enumerate(blocks):
            if "<disabled>yes</disabled>" not in block:
                violations.append(f"block #{i}: not disabled by default")
            if "<timeout>" not in block:
                violations.append(f"block #{i}: missing <timeout>")
            if not re.search(r"<rules_id>\d+</rules_id>", block):
                violations.append(f"block #{i}: missing <rules_id>")
            # Wazuh OR's matchers — `<level>` next to `<rules_id>` broadens
            # the block. Reject the combination.
            if "<level>" in block and "<rules_id>" in block:
                violations.append(
                    f"block #{i}: `<level>` AND `<rules_id>` together — "
                    f"Wazuh OR's matchers; drop the `<level>`",
                )
        assert not violations, "Carve-outs not enforced in source:\n  " + "\n  ".join(
            violations,
        )

    def test_manager_conf_uses_wrapper_for_firewall_drop_blocks(self) -> None:
        """No <active-response> block in source may reference bare
        `firewall-drop` — every block that wants firewall-drop semantics
        must use the `aptl-firewall-drop` wrapper."""
        content = SRC_MANAGER_CONF.read_text()
        blocks = re.findall(
            r"^\s*<active-response>.*?</active-response>",
            content,
            re.DOTALL | re.MULTILINE,
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

    def _run_wrapper(self, tmp_path: Path, payload: str, iptables: str = "/bin/true") -> tuple[subprocess.CompletedProcess, Path]:
        """Helper: run the source wrapper with a temp whitelist + log
        and a mock iptables. Returns (result, log_path)."""
        wl = tmp_path / "whitelist"
        wl.write_text("172.20.4.30\n")
        log = tmp_path / "log"
        env = {
            **os.environ,
            "APTL_AR_WHITELIST": str(wl),
            "APTL_AR_IPTABLES": iptables,
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
        return result, log

    def test_wrapper_script_rejects_invalid_ipv4(self, tmp_path: Path) -> None:
        """The wrapper's IPv4 validation must reject a srcip with an
        embedded newline + whitelisted IP. Without validation,
        `grep -Fxq` would match the embedded whitelisted line and
        short-circuit. With validation, the wrapper logs the rejection
        and exits 0 without invoking iptables — so /bin/false mock for
        iptables doesn't matter; we just verify no SKIPPED log line
        and a 'rejecting invalid srcip' line is present."""
        payload = json.dumps(
            {
                "command": "add",
                "parameters": {
                    "alert": {"data": {"srcip": "evil\n172.20.4.30"}},
                },
            },
        )
        result, log = self._run_wrapper(tmp_path, payload, iptables="/bin/false")
        # Wrapper returns 0 on rejection (no work to do, no error).
        log_content = log.read_text() if log.exists() else ""
        assert "SKIPPED for whitelisted" not in log_content, (
            "Wrapper short-circuited on a malformed srcip with an "
            "embedded newline — IPv4 validation regression."
        )
        assert "rejecting invalid srcip" in log_content, (
            f"Wrapper did not log a srcip rejection; log content: "
            f"{log_content!r}"
        )

    def test_wrapper_script_short_circuits_valid_whitelisted(self, tmp_path: Path) -> None:
        """Source-level happy-path: a whitelisted IPv4 must short-
        circuit. With APTL_AR_IPTABLES=/bin/false, any iptables call
        propagates a non-zero exit; rc=0 means the wrapper never
        invoked iptables."""
        payload = json.dumps(
            {
                "command": "add",
                "parameters": {"alert": {"data": {"srcip": "172.20.4.30"}}},
            },
        )
        result, log = self._run_wrapper(tmp_path, payload, iptables="/bin/false")
        assert result.returncode == 0, (
            f"Wrapper failed to short-circuit on whitelisted 172.20.4.30; "
            f"rc={result.returncode}, stderr={result.stderr[:200]}"
        )
        assert log.exists() and "SKIPPED for whitelisted 172.20.4.30" in log.read_text(), (
            f"Log file missing or no SKIPPED entry; contents: "
            f"{log.read_text() if log.exists() else '<no file>'}"
        )

    def test_wrapper_script_runs_delete_unconditionally(self, tmp_path: Path) -> None:
        """delete + whitelisted IP must still proceed to the iptables
        delete branch (cleanup is unconditional). With /bin/false
        iptables mock, `iptables -C` returns 1 ('rule not present')
        and the wrapper exits 0 — but the log shows 'removed 0 DROP
        rule(s)', proving the delete branch ran."""
        payload = json.dumps(
            {
                "command": "delete",
                "parameters": {"alert": {"data": {"srcip": "172.20.4.30"}}},
            },
        )
        result, log = self._run_wrapper(tmp_path, payload, iptables="/bin/false")
        assert result.returncode == 0, (
            f"Wrapper rc={result.returncode} on delete; expected 0 "
            f"(no rule to delete is OK). stderr={result.stderr[:200]}"
        )
        log_content = log.read_text() if log.exists() else ""
        assert "removed 0 DROP rule(s) for 172.20.4.30" in log_content, (
            f"Wrapper short-circuited on delete + whitelisted srcip "
            f"(no 'removed' log line). cleanup must always run. "
            f"Log: {log_content!r}"
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
