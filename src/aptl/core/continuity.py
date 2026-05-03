"""Orchestrator-side purple-team continuity carve-out (issue #252).

Detects and reverts *blanket* kali source-IP DROP rules on target
containers. Complements ADR-021's in-band ``aptl-firewall-drop``
whitelist by catching out-of-band paths (custom AR scripts, raw
iptables in a Wazuh manager command field, etc.) that bypass the
wrapper.

The audit must preserve granular defensive actions: rules qualified by
port, protocol, payload, interface, or any other matcher are valid blue
tradecraft and stay. Only rules of the shape
``-A INPUT -s <kali_ip>[/32] -j DROP|REJECT`` — with no other matchers —
are reverted.

See ADR-024 for the full design and ADR-021 for the in-band counterpart.
"""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol

from aptl.utils.logging import get_logger


log = get_logger("continuity")


# Default target containers for the carve-out audit. Names are docker
# container names (``aptl-<svc>``) — the same form
# ``backend.container_exec`` expects. Set mirrors the in-process Wazuh
# agents installed by #248. ``aptl-db`` is excluded because postgres
# still ships with a sidecar agent (deferred per #248); iptables on a
# sidecar's namespace doesn't affect the target. A unit test
# (``test_default_targets_are_real_compose_services``) catches drift
# if a service is renamed in docker-compose.yml.
_DEFAULT_TARGETS = (
    "aptl-webapp",
    "aptl-fileshare",
    "aptl-ad",
    "aptl-dns",
    "aptl-victim",
    "aptl-workstation",
)


def default_targets() -> list[str]:
    """Return the canonical target container set for the audit."""
    return list(_DEFAULT_TARGETS)


# Action enum for events.jsonl. Stable surface.
CarveOutAction = Literal["REVERTED", "REVERT_FAILED"]


class _ContainerExecBackend(Protocol):
    """Protocol slice of ``DeploymentBackend`` that this module uses.

    Mirrors :meth:`aptl.core.deployment.backend.DeploymentBackend.container_exec`
    so tests can stub the backend without depending on a Docker daemon.
    """

    def container_exec(
        self,
        name: str,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


# `iptables -S` exec timeout. Bounded per codex's runtime-architecture
# guardrail on subprocess calls. iptables is fast; 10s is generous.
_IPTABLES_TIMEOUT_S = 10


# `iptables -S` records option flags that take a value as separate
# tokens (`-s 172.20.4.30`, not `-s=172.20.4.30`). A small allowlist of
# flags-with-values keeps the parser deterministic without pulling in a
# real argument-spec table.
_FLAGS_WITH_VALUE = frozenset({
    "-s", "-d", "-j", "-i", "-o", "-p", "-m",
    "--dport", "--sport", "--dports", "--sports",
    "--reject-with", "--icmp-type", "--state", "--ctstate",
    "--limit", "--limit-burst", "--string", "--algo", "--to",
    "--mac-source", "--uid-owner", "--gid-owner",
})


def kali_source_ips(*, whitelist_path: Path) -> list[str]:
    """Read kali source IPs from the active-response whitelist file.

    The whitelist is the single source of truth (ADR-021): one IPv4 per
    line, ``#``-prefixed comment lines and blank lines ignored. Inline
    comments are not supported (``aptl-firewall-drop`` uses ``grep -Fxq``
    for whole-line matching, so an inline comment would never match
    anything anyway).

    Args:
        whitelist_path: Path to the whitelist file. Caller resolves
            relative to the project root.

    Returns:
        Ordered list of IPv4 strings, in file order. Empty list if the
        file does not exist (treat missing whitelist as "no protected
        sources" so the audit silently no-ops in environments without
        the lab — the worst-case behavior is still safe).
    """
    if not whitelist_path.exists():
        return []

    ips: list[str] = []
    for raw_line in whitelist_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        ips.append(line)
    return ips


@dataclass(frozen=True)
class ParsedRule:
    """A single ``iptables -S`` ``-A`` rule, parsed into anchor fields.

    Attributes:
        chain: Chain name (``INPUT``, ``FORWARD``, ``OUTPUT``, …).
        source: Value of ``-s`` if present, else None.
        action: Value of ``-j`` (``DROP``, ``REJECT``, ``ACCEPT``, …).
        qualifiers: Set of every option-flag that wasn't ``-s``, ``-j``,
            or the ``-A <chain>`` anchor. Non-empty means the rule has
            additional matchers (port, protocol, payload, interface,
            connection state, action modifier) and is therefore granular,
            never blanket. The carve-out audit refuses to revert rules
            with non-empty qualifiers.
        raw: Original rule text from ``iptables -S`` for logging.
        tokens: Reconstructed argv suitable for ``iptables -D`` after
            stripping the leading ``-A`` so callers can swap to ``-D``.
    """

    chain: str
    source: str | None
    action: str
    qualifiers: set[str] = field(default_factory=set)
    raw: str = ""
    tokens: list[str] = field(default_factory=list)


def parse_iptables_rule(line: str) -> ParsedRule | None:
    """Parse one ``iptables -S`` line into a :class:`ParsedRule`.

    Returns None for non-``-A`` lines (``-N`` chain declarations,
    ``-P`` policy lines, blank/garbage input) and for ``-A`` lines that
    lack a ``-j <action>`` clause (malformed). A rule without ``-s`` is
    still parsed (``source=None``); the classifier filters it out
    downstream.

    Notes:
        Treats option flags listed in :data:`_FLAGS_WITH_VALUE` as
        consuming the following token as their value. Other option
        flags (``--syn``, ``--fragment``, …) stand alone. Both shapes
        end up in :attr:`ParsedRule.qualifiers` if not the source or
        action anchors.
    """
    stripped = line.strip()
    if not stripped or not stripped.startswith("-A "):
        return None

    tokens = stripped.split()
    # Require at minimum: -A <chain> -j <action>. The shortest valid
    # rule has 4 tokens.
    if len(tokens) < 4 or tokens[0] != "-A":
        return None

    chain = tokens[1]
    rule_tokens = tokens[2:]

    source: str | None = None
    action: str | None = None
    qualifiers: set[str] = set()

    i = 0
    while i < len(rule_tokens):
        flag = rule_tokens[i]
        if not flag.startswith("-"):
            # A bare value with no preceding flag — the line is
            # malformed (or includes shapes the parser doesn't know).
            # Refuse rather than guess.
            return None

        takes_value = flag in _FLAGS_WITH_VALUE
        value = (
            rule_tokens[i + 1]
            if takes_value and i + 1 < len(rule_tokens)
            else None
        )

        if flag == "-s":
            if value is None:
                return None
            source = value
        elif flag == "-j":
            if value is None:
                return None
            action = value
        else:
            qualifiers.add(flag)

        i += 2 if takes_value else 1

    if action is None:
        return None

    return ParsedRule(
        chain=chain,
        source=source,
        action=action,
        qualifiers=qualifiers,
        raw=stripped,
        tokens=rule_tokens,
    )


def _normalize_source(source: str) -> str:
    """Strip a trailing ``/32`` so a host-mask form matches a bare IPv4."""
    if source.endswith("/32"):
        return source[:-3]
    return source


def is_blanket_kali_drop(rule: ParsedRule, kali_ips: set[str]) -> bool:
    """True iff ``rule`` is a blanket kali source-IP DROP/REJECT.

    All four conditions must hold:

    1. Chain is ``INPUT`` — only ingress bans wedge red→target traffic;
       FORWARD and OUTPUT decisions don't.
    2. Action is ``DROP`` or ``REJECT`` — the audit only undoes blocks,
       never permits, transitions, or LOG-only matchers.
    3. Source IP is in ``kali_ips`` — non-kali bans are the defender's
       choice and out of scope.
    4. ``qualifiers`` is empty — any port/protocol/payload/interface/
       connection-state matcher means the rule is granular (and
       therefore valid blue tradecraft).

    Subnet bans (``/24`` etc.) are deliberately excluded — they're a
    different decision class and out of scope here. Single-host
    ``/32`` is treated as equivalent to a bare IPv4.
    """
    if rule.chain != "INPUT":
        return False
    if rule.action not in {"DROP", "REJECT"}:
        return False
    if rule.source is None:
        return False
    normalized = _normalize_source(rule.source)
    if normalized != rule.source and not rule.source.endswith("/32"):
        # Subnet mask other than /32; not in scope.
        return False
    if normalized not in kali_ips:
        return False
    return not rule.qualifiers


@dataclass(frozen=True)
class KaliCarveOutFinding:
    """A blanket kali source-IP rule discovered on a target.

    Attributes:
        target: Container name (e.g. ``"victim"``).
        source_ip: The exact source value as written in iptables
            output, including any ``/32`` suffix. Preserved so the
            ``iptables -D`` argv matches the rule byte-for-byte.
        rule_text: Original ``iptables -S`` line for log/event records.
        delete_args: Argv suitable for ``iptables -D``: chain + every
            matcher token in the order iptables emitted them.
    """

    target: str
    source_ip: str
    rule_text: str
    delete_args: list[str]


def audit_target(
    backend: _ContainerExecBackend,
    target: str,
    kali_ips: set[str],
) -> list[KaliCarveOutFinding]:
    """Inspect one target's INPUT chain and return blanket kali findings.

    Fault-tolerant by design (codex's "warnings and empty results"
    guardrail): if iptables can't be queried — exec raised, container
    missing, returncode non-zero — log a warning and return ``[]`` so
    the rest of the audit continues for other targets.
    """
    try:
        result = backend.container_exec(
            target, ["iptables", "-S", "INPUT"], timeout=_IPTABLES_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 - any failure is non-fatal
        log.warning("iptables -S on %s failed: %s", target, exc)
        return []

    if result.returncode != 0:
        log.warning(
            "iptables -S on %s returned %d: %s",
            target, result.returncode, result.stderr.strip(),
        )
        return []

    findings: list[KaliCarveOutFinding] = []
    for line in result.stdout.splitlines():
        rule = parse_iptables_rule(line)
        if rule is None:
            continue
        if not is_blanket_kali_drop(rule, kali_ips):
            continue
        findings.append(
            KaliCarveOutFinding(
                target=target,
                source_ip=rule.source or "",
                rule_text=rule.raw,
                delete_args=[rule.chain, *rule.tokens],
            )
        )
    return findings


@dataclass(frozen=True)
class KaliCarveOutEvent:
    """A single audit/revert action recorded to events.jsonl.

    Schema is the structured-archive contract for the carve-out (codex's
    "structured timeline/intervention records go to the run store as
    JSON/JSONL" guardrail). Adding a field is backward-compatible;
    renaming or removing one is not.
    """

    timestamp: str  # UTC ISO-8601
    target: str
    source_ip: str
    rule_text: str
    action: CarveOutAction
    error: str | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def revert_finding(
    backend: _ContainerExecBackend,
    finding: KaliCarveOutFinding,
) -> KaliCarveOutEvent:
    """Run ``iptables -D <delete_args>`` and return the resulting event.

    On any failure (exec exception or non-zero exit) returns an event
    with ``action="REVERT_FAILED"`` and a populated ``error`` field.
    The audit logs the failure but never raises; callers see a clear
    record in the event stream.
    """
    cmd = ["iptables", "-D", *finding.delete_args]
    error: str | None = None
    success = False
    try:
        result = backend.container_exec(
            finding.target, cmd, timeout=_IPTABLES_TIMEOUT_S,
        )
        if result.returncode == 0:
            success = True
        else:
            error = (
                result.stderr.strip()
                or f"iptables -D returned {result.returncode}"
            )
    except Exception as exc:  # noqa: BLE001 - any failure is non-fatal
        error = f"{type(exc).__name__}: {exc}"

    if success:
        log.info(
            "Reverted blanket kali rule on %s: %s",
            finding.target, finding.rule_text,
        )
    else:
        log.warning(
            "Failed to revert blanket kali rule on %s (%s): %s",
            finding.target, finding.rule_text, error,
        )

    return KaliCarveOutEvent(
        timestamp=_utc_now_iso(),
        target=finding.target,
        source_ip=finding.source_ip,
        rule_text=finding.rule_text,
        action="REVERTED" if success else "REVERT_FAILED",
        error=error,
    )


class _RunStoreProto(Protocol):
    """Protocol slice of :class:`aptl.core.runstore.RunStorageBackend`."""

    def write_jsonl(
        self, run_id: str, relative_path: str, records: list[dict]
    ) -> None: ...


def audit_and_revert(
    backend: _ContainerExecBackend,
    targets: list[str],
    *,
    kali_ips: set[str],
    run_store: _RunStoreProto | None = None,
    run_id: str | None = None,
) -> list[KaliCarveOutEvent]:
    """Audit every target and revert every blanket kali drop found.

    Args:
        backend: Deployment backend (provides ``container_exec``).
        targets: Target container names.
        kali_ips: Source IPs the carve-out protects (from
            :func:`kali_source_ips`).
        run_store: Optional run-archive backend. When given alongside
            ``run_id``, every event is appended to
            ``<run>/continuity-events.jsonl``. Skip if no events were
            produced — don't create a phantom empty file.
        run_id: Run identifier in ``run_store``.

    Returns:
        Ordered list of events produced (one per finding reverted or
        attempted). Empty when no targets had blanket kali rules —
        idempotent re-runs are a no-op.
    """
    events: list[KaliCarveOutEvent] = []
    for target in targets:
        for finding in audit_target(backend, target, kali_ips):
            events.append(revert_finding(backend, finding))

    if events and run_store is not None and run_id is not None:
        records = [asdict(event) for event in events]
        run_store.write_jsonl(run_id, "continuity-events.jsonl", records)

    return events
