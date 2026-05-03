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

    def test_rejects_cidr_subnet_entries(self, tmp_path: Path) -> None:
        # Codex security finding S2 (cycle 3): a whitelist entry like
        # 172.20.4.0/24 would cause the audit to revert a defender's
        # blanket subnet ban — out of scope per ADR-024. Reject any
        # entry that isn't a single bare IPv4.
        from aptl.core.continuity import kali_source_ips

        whitelist = tmp_path / "wl"
        whitelist.write_text("172.20.4.0/24\n10.0.0.1\n")

        ips = kali_source_ips(whitelist_path=whitelist)

        assert ips == ["10.0.0.1"]
        assert "172.20.4.0/24" not in ips

    def test_normalizes_slash_32(self, tmp_path: Path) -> None:
        # /32 is the bare-host equivalent and should be accepted, with
        # the suffix stripped so downstream comparisons work uniformly.
        from aptl.core.continuity import kali_source_ips

        whitelist = tmp_path / "wl"
        whitelist.write_text("172.20.4.30/32\n")

        assert kali_source_ips(whitelist_path=whitelist) == ["172.20.4.30"]

    def test_rejects_non_ipv4_garbage(self, tmp_path: Path) -> None:
        from aptl.core.continuity import kali_source_ips

        whitelist = tmp_path / "wl"
        whitelist.write_text("not-an-ip\n300.0.0.1\n10.0.0.5\n")

        assert kali_source_ips(whitelist_path=whitelist) == ["10.0.0.5"]


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

    def test_reject_action_with_reject_with_has_empty_qualifiers(self) -> None:
        # When blue runs `iptables -I INPUT -s <ip> -j REJECT` without
        # an explicit `--reject-with`, iptables auto-inserts the default
        # `--reject-with icmp-port-unreachable` into the running rule
        # set. ``iptables -S`` dumps it back with the modifier visible.
        # Treating that modifier as a qualifier would preserve a rule
        # that's behaviorally a blanket kali REJECT — the audit must
        # revert it. The action modifier is part of the action specifier,
        # not a matcher.
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule(
            "-A INPUT -s 172.20.4.30 -j REJECT --reject-with icmp-port-unreachable"
        )

        assert rule is not None
        assert rule.action == "REJECT"
        assert rule.qualifiers == set()
        # delete_args still carries `--reject-with` so the eventual
        # `iptables -D` matches the rule iptables actually emitted.
        assert "--reject-with" in rule.tokens
        assert "icmp-port-unreachable" in rule.tokens

    def test_comment_module_does_not_count_as_qualifier(self) -> None:
        # `-m comment --comment "<text>"` is annotation-only — the comment
        # match module never restricts packet matching. A blanket kali
        # rule with only a `--comment` annotation is still a wedge and
        # must be reverted; treating `-m`/`--comment` as a qualifier
        # would let blue paper over the wedge with any string.
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule(
            '-A INPUT -s 172.20.4.30 -m comment --comment keep -j DROP'
        )

        assert rule is not None
        assert rule.action == "DROP"
        assert rule.qualifiers == set()
        # delete_args still carries the annotation so the iptables -D
        # matches the rule byte-for-byte.
        assert "-m" in rule.tokens
        assert "comment" in rule.tokens
        assert "--comment" in rule.tokens

    def test_other_match_module_still_counts_as_qualifier(self) -> None:
        # `-m tcp`, `-m state`, `-m conntrack` etc. are *restrictive*.
        # Only `-m comment` is annotation-only; everything else stays
        # in qualifiers.
        from aptl.core.continuity import parse_iptables_rule

        rule = parse_iptables_rule(
            "-A INPUT -s 172.20.4.30 -m state --state NEW -j DROP"
        )

        assert rule is not None
        # `-m state` is a real match module; rule is granular.
        assert rule.qualifiers, "non-comment -m modules are restrictive"

    def test_quoted_comment_with_whitespace_parses(self) -> None:
        # Codex finding C6 (cycle 2): a blue actor could install a
        # blanket kali DROP with a quoted multi-word comment. The
        # plain ``str.split`` parser broke on the quoted whitespace,
        # rejected the rule as malformed, and the audit silently
        # preserved the wedge. ``shlex.split`` handles the quoting.
        from aptl.core.continuity import is_blanket_kali_drop, parse_iptables_rule

        rule = parse_iptables_rule(
            '-A INPUT -s 172.20.4.30 -m comment --comment "manual mistake" -j DROP'
        )

        assert rule is not None
        assert rule.qualifiers == set()
        assert rule.action == "DROP"
        kali_ips = {"172.20.4.30"}
        assert is_blanket_kali_drop(rule, kali_ips) is True

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

    def test_blanket_kali_reject_with_default_reason_is_revertable(
        self, kali_ips: set[str]
    ) -> None:
        # Round-trip: parse what iptables -S actually emits for a bare
        # `iptables -j REJECT`, then classify.
        from aptl.core.continuity import is_blanket_kali_drop, parse_iptables_rule

        rule = parse_iptables_rule(
            "-A INPUT -s 172.20.4.30 -j REJECT --reject-with icmp-port-unreachable"
        )
        assert rule is not None
        assert is_blanket_kali_drop(rule, kali_ips) is True

    def test_blanket_kali_drop_with_only_comment_is_revertable(
        self, kali_ips: set[str]
    ) -> None:
        # A blue actor cannot paper over a wedge by attaching a comment.
        from aptl.core.continuity import is_blanket_kali_drop, parse_iptables_rule

        rule = parse_iptables_rule(
            '-A INPUT -s 172.20.4.30 -m comment --comment whatever -j DROP'
        )
        assert rule is not None
        assert is_blanket_kali_drop(rule, kali_ips) is True

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


def _stub_key(name: str, cmd: list[str]) -> tuple[str, str, str]:
    """Compose a routing key that distinguishes audit (`-S`) from delete (`-D`).

    Codex finding C9 (cycle 2): keying on (name, cmd[0]) only meant
    `iptables -S` and `iptables -D` shared the same canned response,
    so orchestration tests couldn't pin per-phase behavior.
    """
    head = cmd[0] if cmd else ""
    sub = cmd[1] if len(cmd) > 1 else ""
    return (name, head, sub)


class _StubBackend:
    """Minimal backend stub that captures calls and serves canned output.

    Mirrors the slice of ``DeploymentBackend`` that
    :mod:`aptl.core.continuity` actually uses (``container_exec`` only).
    Each ``container_exec`` call appends to ``calls`` and returns one
    queued ``CompletedProcess``-shaped object. Routing uses
    ``_stub_key`` so audit (`-S`) and delete (`-D`) can be exercised
    independently.
    """

    def __init__(
        self,
        responses: dict[
            tuple[str, str, str], "subprocess.CompletedProcess[str]"
        ] | None = None,
        default_response: "subprocess.CompletedProcess[str] | None" = None,
        raise_for: set[tuple[str, str, str]] | None = None,
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
        key = _stub_key(name, cmd)
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

    def test_raises_on_backend_exception(self, kali_ips: set[str]) -> None:
        # Backend failure is distinguishable from "clean chain". Codex
        # finding C3 (cycle 1): silent empty-list return conflated
        # success with failure; downstream callers (audit_and_revert,
        # the CLI) need the failure signal to surface.
        from aptl.core.continuity import ContinuityAuditError, audit_target

        backend = _StubBackend(raise_for={("nonexistent", "iptables", "-S")})

        with pytest.raises(ContinuityAuditError) as exc_info:
            audit_target(backend, "nonexistent", kali_ips)

        assert "nonexistent" in str(exc_info.value)

    def test_raises_on_nonzero_exit(self, kali_ips: set[str]) -> None:
        from aptl.core.continuity import ContinuityAuditError, audit_target

        backend = _StubBackend(
            default_response=_completed(returncode=1, stderr="iptables: not found"),
        )

        with pytest.raises(ContinuityAuditError):
            audit_target(backend, "victim", kali_ips)


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

        # ``revert_finding`` issues an ``iptables -D ...`` call. The
        # stub raises only on the delete phase so the audit-side test
        # surface stays unaffected.
        backend = _StubBackend(raise_for={("victim", "iptables", "-D")})

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
            ("victim", "iptables", "-S"): _completed(
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

    def test_appends_to_existing_events_jsonl(
        self, kali_ips: set[str], tmp_path: Path
    ) -> None:
        # Codex finding C4 (cycle 1): write_jsonl overwrote, so a
        # second audit invocation in the same run lost the first's
        # evidence. Audit and revert must *append* — every reversion
        # in a run must remain auditable.
        from aptl.core.continuity import audit_and_revert
        from aptl.core.runstore import LocalRunStore

        store = LocalRunStore(tmp_path)
        run_id = "run-append-test"
        store.create_run(run_id)

        # First invocation reverts one rule.
        first_audit_backend = self._audit_backend()
        audit_and_revert(
            first_audit_backend, ["victim"], kali_ips=kali_ips,
            run_store=store, run_id=run_id,
        )

        # Second invocation reverts another rule (different target +
        # rule text so the JSONL is identifiable).
        second_audit_backend = _StubBackend(responses={
            ("webapp", "iptables", "-S"): _completed(
                stdout="-A INPUT -s 172.20.1.30 -j DROP\n",
            ),
        })
        audit_and_revert(
            second_audit_backend, ["webapp"], kali_ips=kali_ips,
            run_store=store, run_id=run_id,
        )

        events_path = tmp_path / run_id / "continuity-events.jsonl"
        lines = events_path.read_text().strip().splitlines()
        assert len(lines) == 2, f"expected 2 events appended, got {len(lines)}"
        recs = [json.loads(line) for line in lines]
        targets = {r["target"] for r in recs}
        assert targets == {"victim", "webapp"}

    def test_emits_audit_failed_event_when_backend_fails(
        self, kali_ips: set[str], tmp_path: Path
    ) -> None:
        # Codex finding C3 (cycle 1): backend exec failure must be
        # captured as a structured event, not collapsed into "no
        # findings". audit_and_revert wraps ContinuityAuditError into
        # an AUDIT_FAILED event and continues to the next target.
        from aptl.core.continuity import audit_and_revert

        backend = _StubBackend(raise_for={("victim", "iptables", "-S")})

        events = audit_and_revert(backend, ["victim"], kali_ips=kali_ips)

        assert len(events) == 1
        ev = events[0]
        assert ev.action == "AUDIT_FAILED"
        assert ev.target == "victim"
        assert ev.error is not None

    def test_continues_after_one_target_fails(
        self, kali_ips: set[str]
    ) -> None:
        # First target inspection raises; second target succeeds and
        # surfaces a finding. The audit must not abort on the first
        # failure.
        from aptl.core.continuity import audit_and_revert

        backend = _StubBackend(
            responses={
                ("webapp", "iptables", "-S"): _completed(
                    stdout="-A INPUT -s 172.20.4.30 -j DROP\n",
                ),
            },
            raise_for={("victim", "iptables", "-S")},
        )

        events = audit_and_revert(
            backend, ["victim", "webapp"], kali_ips=kali_ips,
        )

        actions = [e.action for e in events]
        assert "AUDIT_FAILED" in actions
        assert "REVERTED" in actions

    def test_raises_valueerror_on_empty_kali_ips(self) -> None:
        # Codex finding C11 (cycle 3): the CLI guards an empty whitelist,
        # but a programmatic caller (future runtime engine, MCP server)
        # could pass kali_ips=set() by mistake. The core path must
        # refuse so an unprotected audit doesn't masquerade as clean.
        from aptl.core.continuity import audit_and_revert

        backend = _StubBackend(default_response=_completed())

        with pytest.raises(ValueError, match="empty kali_ips"):
            audit_and_revert(backend, ["aptl-webapp"], kali_ips=set())

    def test_audit_and_revert_issues_both_S_and_D_calls(
        self, kali_ips: set[str]
    ) -> None:
        # Codex finding C9 (cycle 2): the previous stub keyed by
        # (name, cmd[0]) collapsed audit (`-S`) and delete (`-D`) into
        # the same canned response, so orchestration tests couldn't
        # actually pin the per-phase argv. With phase-distinct keying,
        # this test asserts that audit_and_revert really issues both
        # the inspection and the deletion.
        from aptl.core.continuity import audit_and_revert

        backend = _StubBackend(
            responses={
                ("webapp", "iptables", "-S"): _completed(
                    stdout="-A INPUT -s 172.20.4.30 -j DROP\n",
                ),
            },
            # Default response for any other call (i.e. the -D) is
            # success/empty.
            default_response=_completed(),
        )

        audit_and_revert(backend, ["webapp"], kali_ips=kali_ips)

        phases = {(c.cmd[0], c.cmd[1]) for c in backend.calls}
        assert ("iptables", "-S") in phases
        assert ("iptables", "-D") in phases


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

    def test_targets_match_in_process_agent_set(self) -> None:
        # The audit only works on containers that have NET_ADMIN AND
        # an in-process Wazuh agent (#248 / ADR-020). default_targets()
        # must equal the canonical IN_PROCESS_TARGETS used by the
        # active-response tests; including non-NET_ADMIN containers
        # (victim, workstation) would silently produce AUDIT_FAILED
        # events on every invocation. Codex finding C1 (cycle 1).
        from aptl.core.continuity import default_targets
        from tests.test_wazuh_active_response import IN_PROCESS_TARGETS

        assert tuple(default_targets()) == IN_PROCESS_TARGETS

    def test_every_default_target_has_net_admin(self) -> None:
        # Drift guard: if anyone removes NET_ADMIN from one of the
        # default targets in compose, this test fails before the audit
        # silently breaks in production.
        from aptl.core.continuity import default_targets

        compose_text = (PROJECT_ROOT / "docker-compose.yml").read_text()

        for target in default_targets():
            # Locate the per-service block by container_name and walk
            # forward until the next service to find that target's
            # cap_add list.
            anchor = f"container_name: {target}\n"
            idx = compose_text.find(anchor)
            assert idx >= 0, f"no compose entry for {target}"
            # Slice from this anchor to the next "container_name:" or
            # the end of the file — that's roughly this service's body.
            tail = compose_text[idx:]
            next_anchor = tail.find("\n    container_name: ", 1)
            block = tail[:next_anchor] if next_anchor > 0 else tail
            assert "NET_ADMIN" in block, (
                f"{target} compose block lacks NET_ADMIN; iptables audit"
                " will fail there. Either add the cap or remove the"
                " target from default_targets()."
            )


# Reused live-lab target. ``aptl-webapp`` is in IN_PROCESS_TARGETS
# (#248) — NET_ADMIN cap + in-process Wazuh agent — so iptables in its
# namespace works under ``docker exec``. ``aptl-victim`` ships without
# NET_ADMIN (codex finding C1, cycle 1) and is not in default_targets,
# so it's not a valid live-lab integration target for this audit.
_LIVE_TARGET = "aptl-webapp"
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
