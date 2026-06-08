"""Unit tests for run storage backend."""

import json

from aptl.core.runstore import LocalRunStore


class TestLocalRunStore:
    """Tests for the local filesystem run store."""

    def test_create_run(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_dir = store.create_run("abc123")
        assert run_dir.exists()
        assert run_dir.name == "abc123"

    def test_write_file(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_file("r1", "test.txt", b"hello world")
        assert (tmp_path / "runs" / "r1" / "test.txt").read_bytes() == b"hello world"

    def test_write_file_nested(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_file("r1", "sub/dir/file.txt", b"nested")
        assert (tmp_path / "runs" / "r1" / "sub" / "dir" / "file.txt").read_bytes() == b"nested"

    def test_write_json(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        # Use non-sensitive keys: `key` would be redacted at the
        # persistence boundary (ADR-029). Coverage of the redacting
        # path lives in TestLocalRunStoreRedaction below.
        store.write_json("r1", "data.json", {"name": "value", "num": 42})

        data = json.loads((tmp_path / "runs" / "r1" / "data.json").read_text())
        assert data == {"name": "value", "num": 42}

    def test_write_jsonl(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        records = [{"a": 1}, {"b": 2}, {"c": 3}]
        store.write_jsonl("r1", "events.jsonl", records)

        lines = (tmp_path / "runs" / "r1" / "events.jsonl").read_text().strip().splitlines()
        assert len(lines) == 3
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}
        assert json.loads(lines[2]) == {"c": 3}

    def test_write_jsonl_empty(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_jsonl("r1", "empty.jsonl", [])

        content = (tmp_path / "runs" / "r1" / "empty.jsonl").read_bytes()
        assert content == b""

    def test_copy_file(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")

        source = tmp_path / "source.yaml"
        source.write_text("scenario: test\n")

        store.copy_file("r1", "scenario/definition.yaml", source)
        copied = tmp_path / "runs" / "r1" / "scenario" / "definition.yaml"
        assert copied.read_text() == "scenario: test\n"

    def test_list_runs_empty(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        assert store.list_runs() == []

    def test_list_runs(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")

        # Create two runs with manifests
        store.create_run("run-a")
        store.write_json("run-a", "manifest.json", {"run_id": "run-a"})
        store.create_run("run-b")
        store.write_json("run-b", "manifest.json", {"run_id": "run-b"})

        # Create a directory without manifest (should be excluded)
        (tmp_path / "runs" / "no-manifest").mkdir()

        runs = store.list_runs()
        assert "run-a" in runs
        assert "run-b" in runs
        assert "no-manifest" not in runs

    def test_get_run_manifest(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")

        manifest = {"run_id": "r1", "scenario_id": "test"}
        store.write_json("r1", "manifest.json", manifest)

        loaded = store.get_run_manifest("r1")
        assert loaded["run_id"] == "r1"
        assert loaded["scenario_id"] == "test"

    def test_get_run_manifest_not_found(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        import pytest
        with pytest.raises(FileNotFoundError):
            store.get_run_manifest("nonexistent")

    def test_get_run_path(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        path = store.get_run_path("r1")
        assert path == tmp_path / "runs" / "r1"

    def test_list_runs_nonexistent_base(self, tmp_path):
        store = LocalRunStore(tmp_path / "nonexistent")
        assert store.list_runs() == []


class TestLocalRunStoreRedaction:
    """The local run store is the Python persistence boundary for run
    archives (ADR-029): control-plane secrets are redacted before bytes
    hit disk. Opaque bytes / copied files are out of scope by design —
    callers must not route control-plane secrets through write_file /
    copy_file."""

    def test_write_json_redacts_sensitive_keys(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_json("r1", "data.json", {"api_key": "SECRET_AK", "host": "h"})
        data = json.loads((tmp_path / "runs" / "r1" / "data.json").read_text())
        assert data == {"api_key": "[REDACTED]", "host": "h"}

    def test_write_json_redacts_inline_secret_in_string_value(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_json(
            "r1",
            "logs.json",
            {"container": "svc", "log": "boot ok; Authorization: Bearer XYZ.TOKEN"},
        )
        text = (tmp_path / "runs" / "r1" / "logs.json").read_text()
        assert "XYZ.TOKEN" not in text
        assert "Bearer [REDACTED]" in text
        assert "svc" in text

    def test_write_json_redacts_nested(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_json(
            "r1", "n.json", {"svc": {"password": "p", "url": "https://x"}}
        )
        data = json.loads((tmp_path / "runs" / "r1" / "n.json").read_text())
        assert data == {"svc": {"password": "[REDACTED]", "url": "https://x"}}

    def test_write_jsonl_redacts_each_record(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_jsonl(
            "r1", "ev.jsonl", [{"token": "t1", "ok": True}, {"secret": "s2"}]
        )
        lines = (tmp_path / "runs" / "r1" / "ev.jsonl").read_text().strip().splitlines()
        assert json.loads(lines[0]) == {"token": "[REDACTED]", "ok": True}
        assert json.loads(lines[1]) == {"secret": "[REDACTED]"}

    def test_append_jsonl_redacts_each_record(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.append_jsonl("r1", "ev.jsonl", [{"jwt": "ey.signed"}])
        store.append_jsonl("r1", "ev.jsonl", [{"keep": "me"}])
        lines = (tmp_path / "runs" / "r1" / "ev.jsonl").read_text().strip().splitlines()
        assert json.loads(lines[0]) == {"jwt": "[REDACTED]"}
        assert json.loads(lines[1]) == {"keep": "me"}

    def test_non_sensitive_payloads_unchanged(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        payload = {"run_id": "r1", "containers": ["a", "b"], "flags_captured": 3}
        store.write_json("r1", "manifest.json", payload)
        assert json.loads((tmp_path / "runs" / "r1" / "manifest.json").read_text()) == payload

    def test_write_file_and_copy_file_are_byte_passthrough(self, tmp_path):
        # write_file/copy_file move opaque bytes and arbitrary files; they
        # do not (and cannot) structurally redact. ADR-029 says callers
        # must not route control-plane secrets here. The contract is "no
        # transformation" — a regression that quietly wired redact()
        # through these paths is exactly what this test pins, so use
        # credential-shaped content that WOULD become `[REDACTED]` if
        # such a regression slipped in. Innocuous bytes round-trip
        # either way and don't pin the contract.
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_file("r1", "blob.bin", b"password=hunter2&token=abc.def")
        assert (
            (tmp_path / "runs" / "r1" / "blob.bin").read_bytes()
            == b"password=hunter2&token=abc.def"
        )
        source = tmp_path / "evidence.txt"
        source.write_text("evidence: api_key=SECRET_AK\nAuthorization: Bearer xyz\n")
        store.copy_file("r1", "ev/evidence.txt", source)
        assert (
            (tmp_path / "runs" / "r1" / "ev" / "evidence.txt").read_text()
            == "evidence: api_key=SECRET_AK\nAuthorization: Bearer xyz\n"
        )


class TestLocalRunStoreRedactionDefaultHook:
    """Regression test for codex review cycle 1, finding 1: when
    ``json.dumps(redact(obj), default=str)`` reached a non-JSON value
    under a non-sensitive key, ``default=str`` produced a string AFTER
    redaction had already run, smuggling secret-shaped content past the
    boundary. The boundary now routes ``default`` back through
    ``redact``."""

    def test_exception_value_under_non_sensitive_key_is_redacted(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")

        class _Boom:
            def __str__(self) -> str:
                return "fail: Authorization: Bearer XYZ.TOKEN"

        store.write_json("r1", "evt.json", {"event": "boot", "detail": _Boom()})
        text = (tmp_path / "runs" / "r1" / "evt.json").read_text()
        assert "XYZ.TOKEN" not in text
        assert "Bearer [REDACTED]" in text

    def test_exception_value_in_jsonl_is_redacted(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")

        class _Boom:
            def __str__(self) -> str:
                return "password=hunter2"

        store.append_jsonl("r1", "ev.jsonl", [{"obj": _Boom()}])
        text = (tmp_path / "runs" / "r1" / "ev.jsonl").read_text()
        assert "hunter2" not in text
        assert "[REDACTED]" in text


class TestLocalRunStoreRedactionArgvShape:
    """Codex review cycle 3 finding 2: argv-array shapes (collectors /
    MCP traces commonly persist ``{"args": [tool, "-p", value, …]}``)
    must arrive on disk redacted. The runstore is the persistence
    boundary — its contract is "control-plane-secret-safe by
    construction" regardless of whether the command is a scalar string
    or a structured argv."""

    def test_argv_short_p_in_jsonl_is_redacted(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_jsonl(
            "r1",
            "ev.jsonl",
            [{"args": ["hydra", "-p", "hunter2", "host", "ssh"], "rc": 0}],
        )
        text = (tmp_path / "runs" / "r1" / "ev.jsonl").read_text()
        assert "hunter2" not in text
        assert '"rc":0' in text

    def test_argv_short_h_hash_in_json_is_redacted(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("r1")
        store.write_json(
            "r1",
            "evt.json",
            {"args": ["nxc", "smb", "dc", "-u", "alice", "-H", "AAD3:8846"]},
        )
        text = (tmp_path / "runs" / "r1" / "evt.json").read_text()
        assert "AAD3:8846" not in text
        assert "alice" in text  # bare username preserved


class TestSessionScopedHelpers:
    """OBS-003: per-session subdirectories under a run.

    Sessions are MCP-level SSH sessions; many can exist per run. The
    helpers compose under the existing run-id directory contract so a
    full run looks like:

        <base>/<run_id>/
          mcp-side/
            tool-calls.jsonl
            ocsf.jsonl
            sessions/<session_id>.jsonl
          kali-side/
            <session_id>/{pty,pcap,audit,proc-acct}/...
    """

    def test_mcp_side_dir(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("run-A")
        d = store.mcp_side_dir("run-A")
        assert d == tmp_path / "runs" / "run-A" / "mcp-side"

    def test_kali_side_session_dir(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("run-A")
        d = store.kali_side_session_dir("run-A", "sess-1")
        assert d == tmp_path / "runs" / "run-A" / "kali-side" / "sess-1"

    def test_mcp_session_jsonl_path(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run("run-A")
        p = store.mcp_session_jsonl("run-A", "sess-1")
        assert p == tmp_path / "runs" / "run-A" / "mcp-side" / "sessions" / "sess-1.jsonl"

    def test_session_id_validation_rejects_path_traversal(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        import pytest as _pytest

        for bad in ["../escape", "sess/with/slash", "sess..", ".."]:
            with _pytest.raises(ValueError):
                store.kali_side_session_dir("run-A", bad)
            with _pytest.raises(ValueError):
                store.mcp_session_jsonl("run-A", bad)

    def test_run_id_validation_rejects_path_traversal(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        import pytest as _pytest

        for bad in ["../escape", "run/with/slash", ".."]:
            with _pytest.raises(ValueError):
                store.mcp_side_dir(bad)
            with _pytest.raises(ValueError):
                store.kali_side_session_dir(bad, "sess-1")


class TestResolveActiveRunDir:
    """OBS-003: resolve the active scenario's run dir from trace-context.json.

    The MCP servers use this to write per-run captures without taking
    an explicit run_id from each tool caller. Returns ``None`` cleanly
    when no scenario is active (no trace-context.json present), so
    standalone MCP invocations don't error — the caller decides whether
    to fall back to an ``_unbound`` directory or skip writing.
    """

    def test_returns_none_when_no_trace_context(self, tmp_path):
        from aptl.core.runstore import resolve_active_run_dir

        assert resolve_active_run_dir(tmp_path / "state") is None

    def test_returns_run_dir_keyed_by_trace_id(self, tmp_path):
        from aptl.core.runstore import resolve_active_run_dir

        state = tmp_path / "state"
        state.mkdir()
        trace_id = "a" * 32
        (state / "trace-context.json").write_text(
            json.dumps({"trace_id": trace_id, "span_id": "b" * 16, "trace_flags": "01"})
        )
        result = resolve_active_run_dir(state)
        assert result == state / "runs" / trace_id

    def test_returns_none_when_trace_context_malformed(self, tmp_path):
        from aptl.core.runstore import resolve_active_run_dir

        state = tmp_path / "state"
        state.mkdir()
        (state / "trace-context.json").write_text("not json")
        assert resolve_active_run_dir(state) is None

    def test_returns_none_when_trace_context_missing_trace_id(self, tmp_path):
        from aptl.core.runstore import resolve_active_run_dir

        state = tmp_path / "state"
        state.mkdir()
        (state / "trace-context.json").write_text(json.dumps({"span_id": "b" * 16}))
        assert resolve_active_run_dir(state) is None

    def test_rejects_trace_id_with_path_traversal_chars(self, tmp_path):
        from aptl.core.runstore import resolve_active_run_dir

        state = tmp_path / "state"
        state.mkdir()
        (state / "trace-context.json").write_text(
            json.dumps({"trace_id": "../escape", "span_id": "b" * 16})
        )
        # Invariant: trace_id from a malformed/hostile source must not
        # let an attacker write outside the runs/ dir. Reject defensively.
        assert resolve_active_run_dir(state) is None
