"""Issue #912: the readiness probe scripts themselves, run rather than stubbed.

Stubbing a probe's already-parsed output tests the parser and nothing else. The
two properties that matter most here live in the shell and Python the probes
actually execute: telemetry must be attributed by parsed record fields, and no
credential may reach a descendant process's argv.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aptl_techvault.evidence import techvault_readiness_probes as probes

_START = "2026-01-01T00:00:00Z"
_END = "2026-01-01T00:05:00Z"


def _script(name: str) -> str:
    return getattr(probes, name)


def _archive(tmp_path: Path, rows: list[object]) -> str:
    logs = tmp_path / "logs/archives"
    logs.mkdir(parents=True, exist_ok=True)
    (tmp_path / "logs/alerts").mkdir(parents=True, exist_ok=True)
    with (logs / "archives.json").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(row if isinstance(row, str) else json.dumps(row))
            handle.write("\n")
    return _script("_WAZUH_TELEMETRY_SCRIPT").replace(
        "/var/ossec/logs", str(tmp_path / "logs")
    )


def _count(script: str, agent_id: str = "001") -> int:
    result = subprocess.run(
        ["sh", "-s", "--", agent_id, _START, _END],
        input=script,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return int(result.stdout.strip().split("=", 1)[1])


def _event(agent_id: str, timestamp: str, body: str = "ok") -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "agent": {"id": agent_id, "name": f"techvault-{agent_id}"},
        "full_log": body,
    }


def test_the_probe_counts_events_attributed_to_the_agent_in_the_window(tmp_path):
    script = _archive(
        tmp_path,
        [
            _event("001", "2026-01-01T00:01:00Z"),
            _event("001", "2026-01-01T00:02:00Z"),
        ],
    )

    assert _count(script) == 2


def test_events_outside_the_window_are_not_counted(tmp_path):
    """The window bound has to survive the parse; an off-by-one silently
    excluded every real timestamp when the field was sliced by offset."""

    script = _archive(
        tmp_path,
        [
            _event("001", "2025-12-31T23:59:59Z"),
            _event("001", "2026-01-01T00:01:00Z"),
            _event("001", "2026-01-01T00:06:00Z"),
        ],
    )

    assert _count(script) == 1


def test_equivalent_timezone_offsets_are_compared_as_instants(tmp_path):
    """Lexical ISO comparison rejects equivalent timestamps with offsets."""

    script = _archive(
        tmp_path,
        [_event("001", "2026-01-01T01:01:00+01:00")],
    )

    assert _count(script) == 1


def test_the_bounded_scan_reads_the_newest_records_not_the_oldest(tmp_path):
    """A busy long-running manager must not hide the capture window at EOF."""

    script = _archive(
        tmp_path,
        [
            _event("001", "2025-12-31T23:00:00Z"),
            _event("001", "2025-12-31T23:01:00Z"),
            _event("001", "2025-12-31T23:02:00Z"),
            _event("001", "2026-01-01T00:01:00Z"),
        ],
    ).replace("MAX_LINES = 200000", "MAX_LINES = 3")

    assert _count(script) == 1


def test_another_agents_event_cannot_forge_freshness_from_its_body(tmp_path):
    """Forwarded log bodies carry unauthenticated participant input.

    Matching the raw line would let a participant write a target agent's id
    into a web request and manufacture fresh telemetry for a silent host.
    """

    script = _archive(
        tmp_path,
        [
            _event("099", "2026-01-01T00:01:00Z", body='GET /?q="id":"001"'),
            _event("099", "2026-01-01T00:02:00Z", body="agent.id=001 id:001"),
        ],
    )

    assert _count(script) == 0


def test_a_partial_or_malformed_record_is_skipped_not_guessed_at(tmp_path):
    script = _archive(
        tmp_path,
        [
            "not json at all",
            {"timestamp": "2026-01-01T00:01:00Z"},
            {"agent": {"id": "001"}},
            {"timestamp": "2026-01-01T00:01:00Z", "agent": "001"},
            _event("001", "2026-01-01T00:01:00Z"),
        ],
    )

    assert _count(script) == 1


def test_a_missing_archive_reports_no_events_rather_than_failing(tmp_path):
    script = _archive(tmp_path, [])

    assert _count(script) == 0


# --------------------------------------------------------------------------
# No credential may reach a descendant process's argv.
# --------------------------------------------------------------------------


_SECRET = "s3cr3t-readiness-probe-value"


def _argv_recorder(tmp_path: Path, *names: str) -> Path:
    """Put fake clients on PATH that record the argv they were called with."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    recorded = tmp_path / "argv.txt"
    for name in names:
        executable = bin_dir / name
        executable.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{recorded}"\n'
            # Enough output for the callers' own parsing to proceed.
            'if [ "$1" = "ping" ] || [ "$2" = "ping" ]; then echo PONG; fi\n'
            'case "$*" in *"config get"*) echo directive; echo no;; esac\n'
            'case "$*" in *events/add*) echo \'{"Event":{"id":"7"}}\';; esac\n'
            f'case "$*" in *events/view*) echo \'{{"info":"MARKER"}}\';; esac\n'
            "exit 0\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
    return recorded


@pytest.mark.parametrize(
    ("script_name", "setup"),
    [("_MISP_CACHE_SCRIPT", "redis-cli"), ("_MISP_API_SCRIPT", "curl")],
)
def test_no_probe_puts_a_credential_in_a_child_process_argv(
    tmp_path, script_name, setup
):
    """`/proc/<pid>/cmdline` is readable by any process in the same namespace.

    The outer `docker exec` keeps the script off the host command line, which
    is necessary and not sufficient: a credential expanded into a curl or
    redis-cli argument is exposed inside the container for as long as that
    client runs.
    """

    recorded = _argv_recorder(tmp_path, setup)
    if setup == "redis-cli":
        # The real cache image has sha256sum; macOS test runners do not. This
        # argv-focused test only needs identical hashes to reach redis-cli.
        digest = tmp_path / "bin/sha256sum"
        digest.write_text("#!/bin/sh\nprintf '%064d  -\\n' 0\n", encoding="utf-8")
        digest.chmod(0o755)
    config = tmp_path / "redis.conf"
    config.write_text(
        f"user default reset on >{_SECRET} ~* +@read +@write "
        "+@connection +@transaction -@dangerous\nappendonly no\n"
        "maxmemory-policy noeviction\n",
        encoding="utf-8",
    )
    script = _script(script_name).replace("/etc/redis/redis.conf", str(config))

    environment = {
        "PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin",
        "ADMIN_KEY": _SECRET,
        "HOME": str(tmp_path),
    }
    subprocess.run(
        ["sh", "-s", "--", "MARKER"],
        input=script,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )

    observed = recorded.read_text(encoding="utf-8") if recorded.exists() else ""
    assert observed.strip(), f"{setup} was never invoked; the test proves nothing"
    assert _SECRET not in observed, observed


def test_misp_probe_deletes_its_event_when_readback_fails(tmp_path):
    """A failed readiness check must not leave probe data in the scenario."""

    recorded = _argv_recorder(tmp_path, "curl")
    script = _script("_MISP_API_SCRIPT")
    result = subprocess.run(
        ["sh", "-s", "--", "EXPECTED-MARKER"],
        input=script,
        capture_output=True,
        text=True,
        env={
            "PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin",
            "ADMIN_KEY": _SECRET,
            "HOME": str(tmp_path),
        },
        cwd=tmp_path,
    )

    assert result.returncode != 0
    calls = recorded.read_text(encoding="utf-8")
    assert "events/delete/7" in calls


def test_misp_probe_rejects_header_injection_before_curl(tmp_path):
    recorded = _argv_recorder(tmp_path, "curl")

    result = subprocess.run(
        ["sh", "-s", "--", "MARKER"],
        input=_script("_MISP_API_SCRIPT"),
        capture_output=True,
        text=True,
        env={
            "PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin",
            "ADMIN_KEY": "safe\nInjected: header",
            "HOME": str(tmp_path),
        },
        cwd=tmp_path,
    )

    assert result.returncode != 0
    assert not recorded.exists()
