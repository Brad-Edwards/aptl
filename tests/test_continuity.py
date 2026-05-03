"""Verify orchestrator-side purple-team continuity carve-out (issue #252).

Complements ADR-021's in-band whitelist. The audit detects and reverts
*blanket* kali source-IP DROP rules on target containers — rules that
would wedge the loop after iteration 1 by banning kali entirely. The
audit must preserve granular defensive actions (port-, payload-, or
behavior-qualified rules) which are valid blue tradecraft.

Test layout mirrors ``tests/test_wazuh_active_response.py``:

- Source/unit suites (no marker) run everywhere. They drive the parser,
  classifier, kali-IP loader, audit/revert orchestration, and
  run-archive integration via stub backends.
- ``TestContinuityIntegration`` is marked ``LIVE_LAB`` and runs only
  with ``APTL_SMOKE=1``. Injects iptables rules into the running lab
  and asserts the audit behaves correctly end-to-end.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.helpers import LIVE_LAB, docker_exec


PROJECT_ROOT = Path(__file__).resolve().parent.parent
WHITELIST_PATH = (
    PROJECT_ROOT / "config" / "wazuh_cluster" / "etc" / "lists"
    / "active-response-whitelist"
)


class TestKaliSourceIps:
    """The whitelist file is the single source of truth for kali IPs."""

    def test_reads_documented_kali_ips_from_whitelist(self) -> None:
        from aptl.core.continuity import kali_source_ips

        ips = kali_source_ips(whitelist_path=WHITELIST_PATH)

        # Documented IPs from config/wazuh_cluster/etc/lists/
        # active-response-whitelist (also kali's three lab interfaces in
        # docker-compose.yml).
        assert "172.20.4.30" in ips
        assert "172.20.1.30" in ips
        assert "172.20.2.35" in ips

    def test_skips_comments_and_blank_lines(self, tmp_path: Path) -> None:
        from aptl.core.continuity import kali_source_ips

        whitelist = tmp_path / "wl"
        whitelist.write_text(
            "# leading comment\n"
            "\n"
            "10.0.0.1\n"
            "  # indented comment\n"
            "10.0.0.2\n"
            "\n"
        )

        ips = kali_source_ips(whitelist_path=whitelist)

        assert ips == ["10.0.0.1", "10.0.0.2"]

    def test_returns_empty_list_when_whitelist_missing(
        self, tmp_path: Path
    ) -> None:
        from aptl.core.continuity import kali_source_ips

        missing = tmp_path / "nonexistent"

        assert kali_source_ips(whitelist_path=missing) == []


class TestParseIptablesRule:
    """Tokenize ``iptables -S`` output lines into ParsedRule records."""

    def test_blanket_drop(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule("-A INPUT -s 172.20.4.30/32 -j DROP")

        assert rule is not None
        assert rule.chain == "INPUT"
        assert rule.source == "172.20.4.30/32"
        assert rule.action == "DROP"
        assert rule.qualifiers == set()

    def test_blanket_drop_without_cidr(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule("-A INPUT -s 172.20.4.30 -j DROP")

        assert rule is not None
        assert rule.source == "172.20.4.30"
        assert rule.qualifiers == set()

    def test_payload_qualified(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule(
            "-A INPUT -s 172.20.4.30 -p tcp -m tcp --dport 22 -j DROP"
        )

        assert rule is not None
        # Each non-source/non-target option records as a qualifier so
        # is_blanket_kali_drop later refuses to revert this rule.
        assert rule.qualifiers, "expected qualifiers for payload-scoped rule"

    def test_other_chain(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule("-A FORWARD -s 172.20.4.30 -j DROP")

        assert rule is not None
        assert rule.chain == "FORWARD"

    def test_reject_action(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule(
            "-A INPUT -s 172.20.4.30 -j REJECT --reject-with icmp-port-unreachable"
        )

        assert rule is not None
        assert rule.action == "REJECT"
        # `--reject-with ...` modifies the action, so it's a qualifier:
        # reverting the *bare* form would not match this rule by argv.
        assert rule.qualifiers, "REJECT modifiers count as qualifiers"

    def test_policy_line_is_not_a_rule(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        assert parse_iptables_rule("-P INPUT ACCEPT") is None

    def test_new_chain_line_is_not_a_rule(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        assert parse_iptables_rule("-N CUSTOM_CHAIN") is None

    def test_malformed_returns_none(self) -> None:
        from aptl.core.continuity import parse_iptables_rule

        assert parse_iptables_rule("garbage line here") is None
        assert parse_iptables_rule("") is None
        assert parse_iptables_rule("-A INPUT") is None

    def test_rule_without_source_returns_qualifier_record(self) -> None:
        # Rules without `-s` cannot match a kali source-IP, so they are
        # never blanket-kali-drops. The parser still returns a rule for
        # observability; the classifier filters it out downstream.
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule("-A INPUT -j DROP")

        assert rule is not None
        assert rule.source is None
        assert rule.action == "DROP"


class TestIsBlanketKaliDrop:
    """Classify a ParsedRule as blanket-kali (revertable) or granular."""

    @pytest.fixture
    def kali_ips(self) -> set[str]:
        return {"172.20.4.30", "172.20.1.30", "172.20.2.35"}

    def _rule(
        self,
        *,
        chain: str = "INPUT",
        source: str | None = "172.20.4.30",
        action: str = "DROP",
        qualifiers: set[str] | None = None,
    ):
        from aptl.core.continuity import ParsedRule

        return ParsedRule(
            chain=chain,
            source=source,
            action=action,
            qualifiers=qualifiers or set(),
            raw="(synthetic)",
            tokens=[],
        )

    def test_blanket_kali_drop_is_revertable(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import is_blanket_kali_drop

        assert is_blanket_kali_drop(self._rule(), kali_ips) is True

    def test_blanket_kali_reject_is_revertable(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import is_blanket_kali_drop

        assert is_blanket_kali_drop(self._rule(action="REJECT"), kali_ips) is True

    def test_other_action_is_preserved(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import is_blanket_kali_drop

        # ACCEPT, LOG, RETURN, CUSTOM_CHAIN — never reverted; the audit
        # only undoes blocks, never permits or transitions.
        for action in ["ACCEPT", "LOG", "RETURN", "CUSTOM_CHAIN"]:
            assert (
                is_blanket_kali_drop(self._rule(action=action), kali_ips)
                is False
            )

    def test_non_kali_source_is_preserved(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import is_blanket_kali_drop

        assert (
            is_blanket_kali_drop(self._rule(source="10.0.0.1"), kali_ips)
            is False
        )

    def test_no_source_is_preserved(self, kali_ips: set[str]) -> None:
        # Defender's catch-all DROP without `-s` is their choice; the
        # audit only reverts kali-targeted blanket drops.
        from aptl.core.continuity import is_blanket_kali_drop

        assert is_blanket_kali_drop(self._rule(source=None), kali_ips) is False

    def test_payload_qualifier_is_preserved(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import is_blanket_kali_drop

        rule = self._rule(qualifiers={"-p", "--dport"})

        assert is_blanket_kali_drop(rule, kali_ips) is False

    def test_forward_chain_is_preserved(self, kali_ips: set[str]) -> None:
        # OUTPUT and FORWARD bans don't wedge red→target ingress; only
        # INPUT chain rules are in scope for the carve-out.
        from aptl.core.continuity import is_blanket_kali_drop

        for chain in ["FORWARD", "OUTPUT"]:
            assert (
                is_blanket_kali_drop(self._rule(chain=chain), kali_ips) is False
            )

    def test_cidr_32_normalizes(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import is_blanket_kali_drop

        assert (
            is_blanket_kali_drop(self._rule(source="172.20.4.30/32"), kali_ips)
            is True
        )

    def test_non_32_cidr_is_preserved(self, kali_ips: set[str]) -> None:
        # /24 or other masks are subnet bans, not single-host kali bans.
        # Out of scope for this audit (different decision; see ADR-024).
        from aptl.core.continuity import is_blanket_kali_drop

        assert (
            is_blanket_kali_drop(self._rule(source="172.20.4.0/24"), kali_ips)
            is False
        )


@dataclass
class _StubExecCall:
    """One captured call to ``backend.container_exec``."""

    name: str
    cmd: list[str]
    timeout: int | None


class _StubBackend:
    """Minimal backend stub that captures calls and serves canned output.

    Mirrors the slice of ``DeploymentBackend`` that
    :mod:`aptl.core.continuity` actually uses (``container_exec`` only).
    Each ``container_exec`` call appends to ``calls`` and returns one
    queued ``CompletedProcess``-shaped object.
    """

    def __init__(
        self,
        responses: dict[tuple[str, str], "subprocess.CompletedProcess[str]"]
        | None = None,
        default_response: "subprocess.CompletedProcess[str] | None" = None,
        raise_for: set[tuple[str, str]] | None = None,
    ) -> None:
        self.calls: list[_StubExecCall] = []
        self._responses = responses or {}
        self._default = default_response
        self._raise_for = raise_for or set()

    def container_exec(
        self,
        name: str,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> "subprocess.CompletedProcess[str]":
        self.calls.append(_StubExecCall(name=name, cmd=list(cmd), timeout=timeout))
        head = cmd[0] if cmd else ""
        key = (name, head)
        if key in self._raise_for:
            raise RuntimeError(f"stubbed exec failure for {key}")
        if key in self._responses:
            return self._responses[key]
        if self._default is not None:
            return self._default
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> "subprocess.CompletedProcess[str]":
    return subprocess.CompletedProcess(
        args=["iptables"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# Canned `iptables -S INPUT` output: one blanket kali drop, one
# port-qualified kali drop (must be preserved), one unrelated rule.
_CANNED_IPTABLES_OUTPUT = "\n".join([
    "-P INPUT ACCEPT",
    "-P FORWARD DROP",
    "-A INPUT -s 172.20.4.30/32 -j DROP",
    "-A INPUT -s 172.20.4.30 -p tcp -m tcp --dport 22 -j DROP",
    "-A INPUT -s 10.0.0.99 -j DROP",
    "-A INPUT -p icmp -j ACCEPT",
])


class TestAuditTarget:
    """``audit_target`` runs ``iptables -S INPUT`` and filters findings."""

    @pytest.fixture
    def kali_ips(self) -> set[str]:
        return {"172.20.4.30", "172.20.1.30", "172.20.2.35"}

    def test_runs_iptables_S_INPUT_via_backend_container_exec(
        self, kali_ips: set[str]
    ) -> None:
        from aptl.core.continuity import audit_target

        backend = _StubBackend(default_response=_completed(stdout=_CANNED_IPTABLES_OUTPUT))

        audit_target(backend, "victim", kali_ips)

        # One call, exact argv (no shell-string evaluation per
        # codex's "Avoid shell-string command evaluation" guardrail).
        assert len(backend.calls) == 1
        assert backend.calls[0].name == "victim"
        assert backend.calls[0].cmd == ["iptables", "-S", "INPUT"]

    def test_finds_blanket_kali_drop_only(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import audit_target

        backend = _StubBackend(default_response=_completed(stdout=_CANNED_IPTABLES_OUTPUT))

        findings = audit_target(backend, "victim", kali_ips)

        # Exactly one finding: the blanket /32 kali rule. The port-
        # qualified kali rule, the non-kali source rule, and the policy
        # lines are all preserved.
        assert len(findings) == 1
        finding = findings[0]
        assert finding.target == "victim"
        assert finding.source_ip == "172.20.4.30/32"
        assert finding.rule_text == "-A INPUT -s 172.20.4.30/32 -j DROP"

    def test_finding_carries_delete_args_for_iptables_D(
        self, kali_ips: set[str]
    ) -> None:
        from aptl.core.continuity import audit_target

        backend = _StubBackend(default_response=_completed(stdout=_CANNED_IPTABLES_OUTPUT))

        findings = audit_target(backend, "victim", kali_ips)

        # delete_args must reproduce everything after `-A` so the caller
        # can swap to `iptables -D INPUT -s 172.20.4.30/32 -j DROP`.
        assert findings[0].delete_args == [
            "INPUT", "-s", "172.20.4.30/32", "-j", "DROP"
        ]

    def test_returns_empty_when_iptables_returns_clean_input(
        self, kali_ips: set[str]
    ) -> None:
        from aptl.core.continuity import audit_target

        clean = "-P INPUT ACCEPT\n-A INPUT -p icmp -j ACCEPT\n"
        backend = _StubBackend(default_response=_completed(stdout=clean))

        assert audit_target(backend, "victim", kali_ips) == []

    def test_handles_exec_failure_gracefully(
        self, kali_ips: set[str], caplog
    ) -> None:
        # Codex's "fault-tolerant collection with warnings and empty
        # results" guardrail: a missing/broken target should not crash
        # the audit for the rest of the targets.
        from aptl.core.continuity import audit_target

        backend = _StubBackend(raise_for={("nonexistent", "iptables")})

        with caplog.at_level("WARNING", logger="aptl.continuity"):
            findings = audit_target(backend, "nonexistent", kali_ips)

        assert findings == []
        assert any("nonexistent" in r.message for r in caplog.records)

    def test_handles_nonzero_exit_gracefully(
        self, kali_ips: set[str], caplog
    ) -> None:
        from aptl.core.continuity import audit_target

        backend = _StubBackend(default_response=_completed(returncode=1, stderr="iptables: not found"))

        with caplog.at_level("WARNING", logger="aptl.continuity"):
            findings = audit_target(backend, "victim", kali_ips)

        assert findings == []


def _finding(
    *,
    target: str = "victim",
    source_ip: str = "172.20.4.30/32",
    rule_text: str = "-A INPUT -s 172.20.4.30/32 -j DROP",
    delete_args: list[str] | None = None,
):
    from aptl.core.continuity import KaliCarveOutFinding

    return KaliCarveOutFinding(
        target=target,
        source_ip=source_ip,
        rule_text=rule_text,
        delete_args=delete_args or ["INPUT", "-s", "172.20.4.30/32", "-j", "DROP"],
    )


class TestRevertFinding:
    """``revert_finding`` runs ``iptables -D <delete_args>`` and emits an event."""

    def test_calls_iptables_D_with_exact_argv(self) -> None:
        from aptl.core.continuity import revert_finding

        backend = _StubBackend(default_response=_completed(stdout="", returncode=0))
        finding = _finding()

        revert_finding(backend, finding)

        assert len(backend.calls) == 1
        call = backend.calls[0]
        assert call.name == "victim"
        # Exact argv: `iptables -D INPUT -s 172.20.4.30/32 -j DROP`.
        # Codex's "Avoid shell-string command evaluation" guardrail
        # again — argv only.
        assert call.cmd == [
            "iptables", "-D", "INPUT", "-s", "172.20.4.30/32", "-j", "DROP",
        ]

    def test_returns_reverted_event_on_success(self) -> None:
        from aptl.core.continuity import revert_finding

        backend = _StubBackend(default_response=_completed())
        event = revert_finding(backend, _finding())

        assert event.target == "victim"
        assert event.source_ip == "172.20.4.30/32"
        assert event.rule_text == "-A INPUT -s 172.20.4.30/32 -j DROP"
        assert event.action == "REVERTED"
        assert event.error is None
        # Timestamp is a UTC ISO string. Don't pin format precisely; just
        # confirm the field is populated for events.jsonl auditability.
        assert event.timestamp

    def test_returns_failed_event_on_nonzero_exit(self) -> None:
        from aptl.core.continuity import revert_finding

        backend = _StubBackend(
            default_response=_completed(returncode=1, stderr="bad rule"),
        )

        event = revert_finding(backend, _finding())

        assert event.action == "REVERT_FAILED"
        assert event.error is not None
        assert "bad rule" in event.error

    def test_returns_failed_event_when_exec_raises(self) -> None:
        from aptl.core.continuity import revert_finding

        backend = _StubBackend(raise_for={("victim", "iptables")})

        event = revert_finding(backend, _finding())

        assert event.action == "REVERT_FAILED"
        assert event.error is not None


class TestAuditAndRevert:
    """End-to-end orchestration: audit + revert across targets, with archive."""

    @pytest.fixture
    def kali_ips(self) -> set[str]:
        return {"172.20.4.30", "172.20.1.30", "172.20.2.35"}

    def _audit_backend(self) -> _StubBackend:
        # Backend whose `iptables -S INPUT` returns one blanket kali drop
        # and whose `iptables -D ...` succeeds. Routes per cmd[1] so a
        # single backend serves both phases.
        responses = {
            ("victim", "iptables"): _completed(
                stdout="-A INPUT -s 172.20.4.30/32 -j DROP\n"
            ),
        }
        return _StubBackend(responses=responses)

    def test_returns_events_for_each_finding(
        self, kali_ips: set[str]
    ) -> None:
        from aptl.core.continuity import audit_and_revert

        events = audit_and_revert(self._audit_backend(), ["victim"], kali_ips=kali_ips)

        assert len(events) == 1
        assert events[0].action == "REVERTED"
        assert events[0].target == "victim"

    def test_clean_tree_yields_no_events(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import audit_and_revert

        backend = _StubBackend(default_response=_completed(stdout=""))

        assert audit_and_revert(backend, ["victim"], kali_ips=kali_ips) == []

    def test_idempotent_on_clean_tree(self, kali_ips: set[str]) -> None:
        # Run twice over the same clean backend; second run must also
        # produce no events and no spurious calls beyond audit reads.
        from aptl.core.continuity import audit_and_revert

        backend = _StubBackend(default_response=_completed(stdout=""))

        first = audit_and_revert(backend, ["victim"], kali_ips=kali_ips)
        second = audit_and_revert(backend, ["victim"], kali_ips=kali_ips)

        assert first == [] and second == []
        # Each invocation does exactly one audit call per target; no
        # phantom delete attempts.
        assert all(c.cmd[:2] == ["iptables", "-S"] for c in backend.calls)

    def test_walks_every_target(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import audit_and_revert

        backend = _StubBackend(default_response=_completed(stdout=""))

        audit_and_revert(backend, ["victim", "webapp", "ad"], kali_ips=kali_ips)

        names = {c.name for c in backend.calls if c.cmd[:2] == ["iptables", "-S"]}
        assert names == {"victim", "webapp", "ad"}

    def test_writes_events_jsonl_when_run_store_provided(
        self, kali_ips: set[str], tmp_path: Path
    ) -> None:
        from aptl.core.continuity import audit_and_revert
        from aptl.core.runstore import LocalRunStore

        store = LocalRunStore(tmp_path)
        run_id = "run-abc-123"
        store.create_run(run_id)

        events = audit_and_revert(
            self._audit_backend(),
            ["victim"],
            kali_ips=kali_ips,
            run_store=store,
            run_id=run_id,
        )

        assert len(events) == 1
        events_path = tmp_path / run_id / "continuity-events.jsonl"
        assert events_path.exists()

        # JSONL: one event per line, parseable.
        lines = events_path.read_text().strip().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["target"] == "victim"
        assert rec["action"] == "REVERTED"
        assert rec["source_ip"] == "172.20.4.30/32"
        assert "timestamp" in rec
        assert rec["rule_text"] == "-A INPUT -s 172.20.4.30/32 -j DROP"

    def test_no_jsonl_written_when_no_findings(
        self, kali_ips: set[str], tmp_path: Path
    ) -> None:
        from aptl.core.continuity import audit_and_revert
        from aptl.core.runstore import LocalRunStore

        store = LocalRunStore(tmp_path)
        run_id = "run-clean"
        store.create_run(run_id)

        backend = _StubBackend(default_response=_completed(stdout=""))
        audit_and_revert(
            backend, ["victim"], kali_ips=kali_ips, run_store=store, run_id=run_id,
        )

        events_path = tmp_path / run_id / "continuity-events.jsonl"
        # Empty audit must not create a phantom file.
        assert not events_path.exists()


class TestDefaultTargets:
    """``default_targets`` must match real services in docker-compose.yml."""

    def test_targets_are_real_compose_services(self) -> None:
        from aptl.core.continuity import default_targets

        compose = PROJECT_ROOT / "docker-compose.yml"
        text = compose.read_text()
        # docker-compose service names don't always match container
        # names; the canonical handle is the explicit
        # ``container_name:`` declaration.
        for target in default_targets():
            needle = f"container_name: {target}"
            assert (
                needle in text
            ), f"docker-compose.yml has no '{needle}' declaration"


# Reused live-lab target. ``aptl-victim`` always exists (default lab
# profile) and runs under NET_ADMIN per #248, so iptables works.
_LIVE_TARGET = "aptl-victim"
_KALI_LIVE_IP = "172.20.4.30"


def _live_iptables_clear_kali(target: str = _LIVE_TARGET) -> None:
    """Idempotently delete every kali-related INPUT rule from a target.

    Used as setup/teardown for the integration suite so a previous
    test's leftover rule never fails the next test. ``iptables -D`` of
    a non-present rule errors with returncode 1 — we ignore that on
    cleanup paths.
    """
    # Best-effort delete loop: keep deleting until -D fails. Ten
    # iterations is plenty (the test plants at most a couple of rules).
    for _ in range(10):
        result = docker_exec(
            target,
            ["iptables", "-D", "INPUT", "-s", _KALI_LIVE_IP, "-j", "DROP"],
            timeout=5,
        )
        if result.returncode != 0:
            break
    for _ in range(10):
        result = docker_exec(
            target,
            ["iptables", "-D", "INPUT", "-s", _KALI_LIVE_IP, "-p", "tcp",
             "-m", "tcp", "--dport", "22", "-j", "DROP"],
            timeout=5,
        )
        if result.returncode != 0:
            break


@LIVE_LAB
class TestContinuityIntegration:
    """End-to-end audit on the running lab.

    Requires ``APTL_SMOKE=1`` plus a live ``aptl lab start``. Uses the
    canonical ``DockerComposeBackend`` so the integration tests exercise
    the same code path the CLI does.
    """

    @pytest.fixture
    def backend(self):
        from aptl.core.deployment.docker_compose import DockerComposeBackend

        return DockerComposeBackend(project_dir=PROJECT_ROOT)

    @pytest.fixture
    def kali_ips(self) -> set[str]:
        from aptl.core.continuity import kali_source_ips

        return set(kali_source_ips(whitelist_path=WHITELIST_PATH))

    @pytest.fixture(autouse=True)
    def _cleanup_iptables(self):
        # Pre-clean any leftover state from a prior interrupted test.
        _live_iptables_clear_kali()
        yield
        _live_iptables_clear_kali()

    def test_reverts_blanket_kali_drop(self, backend, kali_ips) -> None:
        from aptl.core.continuity import audit_and_revert

        # Inject the wedge rule.
        injected = docker_exec(
            _LIVE_TARGET,
            ["iptables", "-I", "INPUT", "-s", _KALI_LIVE_IP, "-j", "DROP"],
            timeout=5,
        )
        assert injected.returncode == 0, injected.stderr

        events = audit_and_revert(backend, [_LIVE_TARGET], kali_ips=kali_ips)

        assert len(events) == 1
        assert events[0].action == "REVERTED"
        assert events[0].target == _LIVE_TARGET
        assert _KALI_LIVE_IP in events[0].source_ip

        # Rule is gone.
        verify = docker_exec(
            _LIVE_TARGET, ["iptables", "-S", "INPUT"], timeout=5,
        )
        assert verify.returncode == 0
        assert _KALI_LIVE_IP not in verify.stdout

    def test_preserves_payload_qualified_drop(
        self, backend, kali_ips
    ) -> None:
        # A port-scoped kali drop is valid blue tradecraft — granular
        # hardening, not a wedge. The audit must preserve it.
        from aptl.core.continuity import audit_and_revert

        injected = docker_exec(
            _LIVE_TARGET,
            ["iptables", "-I", "INPUT", "-s", _KALI_LIVE_IP,
             "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "DROP"],
            timeout=5,
        )
        assert injected.returncode == 0, injected.stderr

        events = audit_and_revert(backend, [_LIVE_TARGET], kali_ips=kali_ips)

        assert events == [], f"expected no reversions, got {events}"

        # Granular rule still present.
        verify = docker_exec(
            _LIVE_TARGET, ["iptables", "-S", "INPUT"], timeout=5,
        )
        assert verify.returncode == 0
        assert "--dport 22" in verify.stdout
        assert _KALI_LIVE_IP in verify.stdout

    def test_idempotent_on_clean_target(self, backend, kali_ips) -> None:
        from aptl.core.continuity import audit_and_revert

        first = audit_and_revert(backend, [_LIVE_TARGET], kali_ips=kali_ips)
        second = audit_and_revert(backend, [_LIVE_TARGET], kali_ips=kali_ips)

        assert first == [] and second == []
