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
        store.write_json("r1", "data.json", {"key": "value", "num": 42})

        data = json.loads((tmp_path / "runs" / "r1" / "data.json").read_text())
        assert data == {"key": "value", "num": 42}

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
