"""Bounded native probes behind the two TechVault readiness demands.

Every probe runs inside the container that already holds the credential it
needs, driven by a fixed ``sh -s`` helper whose script arrives on stdin. No
credential is ever read out to the host, placed in argv, or handed back in a
result: the probes return classified outcomes, and the source adapters turn
those into evidence.

The scripts are deliberately small and single-purpose. Each one either proves
the exact fact its demand names or exits non-zero; none of them repairs
anything, and none writes outside the bounded object it created for itself.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Protocol, cast

_MAX_PROBE_BYTES = 64 * 1024
_PROBE_TIMEOUT_SECONDS = 60

MISP_CONTAINER = "aptl-misp"
MISP_DB_CONTAINER = "aptl-misp-db"
MISP_CACHE_CONTAINER = "aptl-misp-redis"
WAZUH_MANAGER_CONTAINER = "aptl-wazuh-manager"


class _ProbeExecutor(Protocol):
    """Callable shape exposed by the deployment backend's stdin executor."""

    def __call__(
        self,
        container: str,
        command: list[str],
        input_text: str,
        *,
        timeout: int,
    ) -> object: ...


def _probe_executor(execute: object) -> _ProbeExecutor | None:
    """Return a statically callable executor after the runtime boundary check."""

    return cast(_ProbeExecutor, execute) if callable(execute) else None


# MISP's own container holds ADMIN_KEY in its admitted environment, so the
# authenticated write/read happens there and the key never leaves it. The probe
# creates one event carrying a collision-resistant marker, reads it back by that
# marker, and deletes it again -- it never touches scenario content.
#
# This probe proves authentication and the data path, not identity: it talks to
# the loopback listener without verifying the certificate, and the result is
# recorded as `api_write_read_ok` alone. Certificate identity is a separate
# fact, proven separately below against the lab CA, so a successful call here
# can never be read as a verified one.
_MISP_API_SCRIPT = r"""
set -eu
marker="$1"
base="https://127.0.0.1:443"
newline='
'
carriage_return="$(printf '\r')"
case "${ADMIN_KEY:-}" in
    ''|*"$newline"*|*"$carriage_return"*)
        echo "invalid MISP administrator key" >&2; exit 1 ;;
esac
# curl reads the authorization value from an owner-only header file. The key
# therefore never enters argv or curl's config grammar.
headers="$(mktemp)"
id=""
cleanup() {
    status="$?"
    trap - EXIT
    if [ -n "$id" ]; then
        curl -ksf -H "@$headers" -X POST "$base/events/delete/$id" \
            >/dev/null 2>&1 || true
    fi
    rm -f "$headers"
    exit "$status"
}
trap cleanup EXIT
umask 077
printf 'Authorization: %s\nAccept: application/json\n' "${ADMIN_KEY}" > "$headers"
created="$(curl -ksf -H "@$headers" -X POST "$base/events/add" \
    -H 'Content-Type: application/json' \
    -d "{\"Event\":{\"info\":\"$marker\",\"distribution\":\"0\",\"analysis\":\"0\",\"threat_level_id\":\"4\"}}")"
id="$(printf '%s' "$created" | sed -nE 's/.*"id":"?([0-9]+)"?.*/\1/p' | head -n 1)"
[ -n "$id" ]
read_back="$(curl -ksf -H "@$headers" "$base/events/view/$id")"
printf '%s' "$read_back" | grep -Fq "$marker"
echo "api_write_read_ok=true"
"""


# The declared application role and database are proven from inside misp-db
# using the credential already in its environment. MYSQL_PWD keeps the password
# out of the command line even inside the container.
_MISP_DB_SCRIPT = r"""
set -eu
MYSQL_PWD="$MYSQL_PASSWORD"
export MYSQL_PWD
out="$(mysql -N -B -u "$MYSQL_USER" -D "$MYSQL_DATABASE" \
    -e 'SELECT DATABASE(), SUBSTRING_INDEX(CURRENT_USER(), "@", 1);')"
db="$(printf '%s' "$out" | cut -f1)"
role="$(printf '%s' "$out" | cut -f2)"
[ -n "$db" ] && [ -n "$role" ]
echo "database_identity=$db"
echo "database_role=$role"
echo "database_role_access_ok=true"
"""

# The cache credential is read from the mounted server configuration inside the
# cache container, so the generated value stays where it was delivered. The
# declared persistence posture is read back from the running server rather than
# assumed from the image's defaults.
_MISP_CACHE_SCRIPT = r"""
set -eu
pass="$(sed -nE 's/^requirepass[[:space:]]+([^[:space:]]+)$/\1/p' /etc/redis/redis.conf)"
[ -n "$pass" ]
# An unauthenticated ping must be refused, or "authenticated access" would be
# indistinguishable from an open cache.
if redis-cli ping 2>&1 | grep -qiv 'NOAUTH'; then
    echo "cache is not requiring authentication" >&2
    exit 1
fi
# REDISCLI_AUTH is redis-cli's own non-argv credential channel. `-a "$pass"`
# would publish the generated cache credential in /proc/<pid>/cmdline for every
# invocation below.
REDISCLI_AUTH="$pass"
export REDISCLI_AUTH
redis-cli --no-auth-warning ping | grep -Fxq PONG
aof="$(redis-cli --no-auth-warning config get appendonly | tail -n 1)"
evict="$(redis-cli --no-auth-warning config get maxmemory-policy | tail -n 1)"
[ -n "$aof" ] && [ -n "$evict" ]
echo "cache_authenticated=true"
echo "cache_persistence_policy=$aof"
echo "cache_eviction_policy=$evict"
"""


# Certificate identity is proven for the name the scenario authored, not for
# whatever name happens to resolve: --resolve pins the authored host to the
# admitted address so a passing result means the leaf really carries that SAN
# and chains to the lab CA.
_MISP_TLS_SCRIPT = r"""
set -eu
host="$1"
address="$2"
curl -sf --cacert /opt/techvault/soc-certs/lab-ca.pem \
    --resolve "$host:443:$address" \
    "https://$host:443/users/login" >/dev/null
echo "certificate_verified=true"
"""


def misp_readiness_probe(
    execute: object,
    *,
    canonical_url: str,
    canonical_host: str,
    misp_address: str,
    verifier_container: str,
) -> Mapping[str, object] | None:
    """Return every MISP readiness fact, or ``None`` when any one is unproven."""

    marker = f"aptl-readiness-{uuid.uuid4()}"
    observed: dict[str, object] = {
        "canonical_url": canonical_url,
        "api_correlation_id": marker,
    }
    steps = (
        (verifier_container, _MISP_TLS_SCRIPT, (canonical_host, misp_address)),
        (MISP_CONTAINER, _MISP_API_SCRIPT, (marker,)),
        (MISP_DB_CONTAINER, _MISP_DB_SCRIPT, ()),
        (MISP_CACHE_CONTAINER, _MISP_CACHE_SCRIPT, ()),
    )
    for container, script, arguments in steps:
        fields = _run_probe(execute, container, script, arguments)
        if fields is None:
            return None
        observed.update(fields)
    return observed


def _run_probe(
    execute: object,
    container: str,
    script: str,
    arguments: tuple[str, ...],
) -> dict[str, object] | None:
    """Run one bounded probe script and parse its ``key=value`` lines."""

    runner = _probe_executor(execute)
    if runner is None:
        return None
    result = runner(
        container,
        ["sh", "-s", "--", *arguments],
        script,
        timeout=_PROBE_TIMEOUT_SECONDS,
    )
    stdout = getattr(result, "stdout", "") or ""
    if getattr(result, "returncode", 1) != 0 or len(stdout.encode()) > _MAX_PROBE_BYTES:
        return None
    return _parse_fields(stdout)


def _parse_fields(stdout: str) -> dict[str, object] | None:
    """Parse an unambiguous ``key=value`` probe response."""

    fields: dict[str, object] = {}
    for line in stdout.splitlines():
        name, separator, value = line.partition("=")
        if not separator or not name.strip():
            return None
        name = name.strip()
        if name in fields:
            return None
        cleaned = value.strip()
        fields[name] = True if cleaned == "true" else cleaned
    return fields


# The manager owns the enrolled roster, so the roster is read from it rather
# than assembled from each host's own claim about itself. `agent_control -l`
# needs no credential and returns the stable id/name/status triple the demand
# correlates on.
_WAZUH_ROSTER_SCRIPT = r"""
set -eu
/var/ossec/bin/agent_control -l
"""

# Enrollment survival is proven from the agent's own retained identity file: a
# regenerated id means the retained state did not survive, whatever the manager
# currently reports.
_WAZUH_AGENT_SCRIPT = r"""
set -eu
id="$(cut -d' ' -f1 /var/ossec/etc/client.keys | head -n 1)"
[ -n "$id" ]
echo "agent_id=$id"
for path in "$@"; do
    [ -r "$path" ] || { echo "unreadable declared source: $path" >&2; exit 1; }
done
echo "sources_readable=true"
"""


def wazuh_roster(execute: object) -> tuple[tuple[str, str, str], ...] | None:
    """Return every ``(enrollment_name, agent_id, status)`` row the manager holds."""

    runner = _probe_executor(execute)
    if runner is None:
        return None
    result = runner(
        WAZUH_MANAGER_CONTAINER,
        ["sh", "-s"],
        _WAZUH_ROSTER_SCRIPT,
        timeout=_PROBE_TIMEOUT_SECONDS,
    )
    stdout = getattr(result, "stdout", "") or ""
    if getattr(result, "returncode", 1) != 0 or len(stdout.encode()) > _MAX_PROBE_BYTES:
        return None
    return _parse_roster(stdout)


def _parse_roster(stdout: str) -> tuple[tuple[str, str, str], ...]:
    """Parse ``agent_control -l`` rows into ``(name, id, status)`` tuples.

    Rows look like ``   ID: 001, Name: techvault-db-agent, IP: any, Active``.
    Anything that does not carry all three fields is ignored rather than
    guessed at, so an unreadable roster yields no identities and fails closed.

    Every row is preserved, including repeats of a name. Keying this by name
    would silently discard the duplicate and stale members the released scope
    requires readiness to reject: the caller cannot reject what the parser
    already collapsed.
    """

    roster: list[tuple[str, str, str]] = []
    for line in stdout.splitlines():
        if "ID:" not in line or "Name:" not in line:
            continue
        parts = [part.strip() for part in line.split(",")]
        fields = {
            key.strip(): value.strip()
            for key, _, value in (part.partition(":") for part in parts)
            if value
        }
        name = fields.get("Name")
        identifier = fields.get("ID")
        status = parts[-1].lower() if parts else ""
        if name and identifier and status:
            roster.append((name, identifier, status))
    return tuple(roster)


# Freshness is an observation, not an inference from connection state. The
# manager records every event it received with the agent id it was attributed
# to, so the probe counts events for that exact id whose timestamp falls inside
# the capture window. A connected agent that stopped shipping fails this.
#
# The records are parsed as JSON and matched on their top-level `agent.id` and
# `timestamp` fields. Substring-matching the raw line would count any event
# whose *body* happened to contain the id -- and forwarded log bodies carry
# unauthenticated participant input, so a participant could write another
# host's id into a web request and manufacture freshness for a silent agent.
# A malformed or partial line is skipped rather than guessed at.
_WAZUH_TELEMETRY_SCRIPT = r"""
set -eu
exec python3 - "$@" <<'PYTHON'
import json
import sys
from datetime import datetime, timezone

agent_id, start, end = sys.argv[1], sys.argv[2], sys.argv[3]
LOGS = (
    "/var/ossec/logs/archives/archives.json",
    "/var/ossec/logs/alerts/alerts.json",
)
MAX_LINES = 200000
MAX_BYTES = 32 * 1024 * 1024

def instant(value):
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp is not timezone-aware")
    return parsed.astimezone(timezone.utc)

def recent_lines(path):
    try:
        handle = open(path, "rb")
    except OSError:
        return ()
    with handle:
        handle.seek(0, 2)
        offset = max(0, handle.tell() - MAX_BYTES)
        handle.seek(offset)
        data = handle.read(MAX_BYTES)
    if offset:
        _partial, separator, data = data.partition(b"\n")
        if not separator:
            return ()
    return data.decode("utf-8", errors="replace").splitlines()[-MAX_LINES:]

try:
    start_at, end_at = instant(start), instant(end)
except (TypeError, ValueError):
    raise SystemExit(2)
if start_at > end_at:
    raise SystemExit(2)

count = 0
for path in LOGS:
    for line in recent_lines(path):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        agent = record.get("agent")
        timestamp = record.get("timestamp")
        if not isinstance(agent, dict) or not isinstance(timestamp, str):
            continue
        if str(agent.get("id", "")) != agent_id:
            continue
        try:
            observed_at = instant(timestamp)
        except (TypeError, ValueError):
            continue
        if start_at <= observed_at <= end_at:
            count += 1
print("telemetry_event_count=%d" % count)
PYTHON
"""


def telemetry_events(
    execute: object, agent_id: str, start_iso: str, end_iso: str
) -> int | None:
    """Return how many events the manager attributed to one id in the window."""

    fields = _run_probe(
        execute,
        WAZUH_MANAGER_CONTAINER,
        _WAZUH_TELEMETRY_SCRIPT,
        (agent_id, start_iso, end_iso),
    )
    if fields is None:
        return None
    try:
        return int(str(fields.get("telemetry_event_count", "")))
    except ValueError:
        return None


def agent_identity(
    execute: object, container: str, declared_sources: tuple[str, ...]
) -> dict[str, object] | None:
    """Return one host's retained agent id and declared-source readability."""

    return _run_probe(execute, container, _WAZUH_AGENT_SCRIPT, declared_sources)


def bounded_json(document: object, limit: int) -> bytes | None:
    """Encode a readiness document only when it fits its admitted bound."""

    try:
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    except (TypeError, ValueError, RecursionError):
        return None
    return raw if len(raw) <= limit else None


__all__ = (
    "MISP_CACHE_CONTAINER",
    "MISP_CONTAINER",
    "MISP_DB_CONTAINER",
    "WAZUH_MANAGER_CONTAINER",
    "agent_identity",
    "bounded_json",
    "misp_readiness_probe",
    "telemetry_events",
    "wazuh_roster",
)
