"""Unit tests for run export functionality."""

import json
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from aptl.core.exporter import export_local, export_s3, _sha256_file
from aptl.core.runstore import LocalRunStore


class TestSha256File:
    """Tests for file hashing utility."""

    def test_hash_known_content(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        digest = _sha256_file(f)
        assert len(digest) == 64
        # Known SHA-256 of "hello world"
        assert digest == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


class TestExportLocal:
    """Tests for local export."""

    def _make_run(self, tmp_path, run_id="test-run"):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run(run_id)
        store.write_json(run_id, "manifest.json", {
            "run_id": run_id,
            "scenario_id": "sc1",
            "scenario_name": "Test Scenario",
        })
        store.write_file(run_id, "data.txt", b"some test data")
        store.write_json(run_id, "wazuh/alerts.json", [{"alert": 1}])
        return store

    def test_export_creates_archive(self, tmp_path):
        store = self._make_run(tmp_path)
        output_dir = tmp_path / "export"

        archive = export_local(store, "test-run", output_dir)

        assert archive.exists()
        assert archive.name == "test-run.tar.gz"
        assert archive.parent == output_dir

    def test_export_archive_contains_files(self, tmp_path):
        store = self._make_run(tmp_path)
        output_dir = tmp_path / "export"

        archive = export_local(store, "test-run", output_dir)

        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
            assert "test-run/manifest.json" in names
            assert "test-run/data.txt" in names
            assert "test-run/wazuh/alerts.json" in names
            assert "test-run/checksums.sha256" in names

    def test_export_checksums_file(self, tmp_path):
        store = self._make_run(tmp_path)
        output_dir = tmp_path / "export"

        export_local(store, "test-run", output_dir)

        checksums_path = store.get_run_path("test-run") / "checksums.sha256"
        assert checksums_path.exists()
        content = checksums_path.read_text()
        assert "manifest.json" in content
        assert "data.txt" in content
        # Each line should have a 64-char hash + two spaces + filename
        for line in content.strip().splitlines():
            parts = line.split("  ", 1)
            assert len(parts) == 2
            assert len(parts[0]) == 64

    def test_export_nonexistent_run(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        import pytest
        with pytest.raises(FileNotFoundError):
            export_local(store, "nonexistent", tmp_path / "export")

    def test_export_creates_output_dir(self, tmp_path):
        store = self._make_run(tmp_path)
        output_dir = tmp_path / "deeply" / "nested" / "dir"

        archive = export_local(store, "test-run", output_dir)
        assert archive.exists()
        assert output_dir.exists()


class TestExportS3:
    """Tests for S3 export (mocked)."""

    def _make_run(self, tmp_path, run_id="test-run"):
        store = LocalRunStore(tmp_path / "runs")
        store.create_run(run_id)
        store.write_json(run_id, "manifest.json", {
            "run_id": run_id,
            "scenario_id": "sc1",
            "scenario_name": "Test Scenario",
        })
        store.write_file(run_id, "data.txt", b"some data")
        return store

    @patch("aptl.core.exporter.boto3", create=True)
    def test_export_s3_returns_uri(self, mock_boto3, tmp_path):
        store = self._make_run(tmp_path)
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        uri = export_s3(store, "test-run", "my-bucket", "runs/", tmp_path / "export")

        assert uri == "s3://my-bucket/runs/test-run.tar.gz"

    @patch("aptl.core.exporter.boto3", create=True)
    def test_export_s3_uploads_archive_and_manifest(self, mock_boto3, tmp_path):
        store = self._make_run(tmp_path)
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        export_s3(store, "test-run", "my-bucket", "runs", tmp_path / "export")

        # Should have called upload_file twice (archive + manifest)
        assert mock_client.upload_file.call_count == 2

        # Check archive upload
        archive_call = mock_client.upload_file.call_args_list[0]
        assert archive_call[0][1] == "my-bucket"
        assert archive_call[0][2] == "runs/test-run.tar.gz"

        # Check manifest upload
        manifest_call = mock_client.upload_file.call_args_list[1]
        assert manifest_call[0][1] == "my-bucket"
        assert manifest_call[0][2] == "runs/test-run/manifest.json"

    @patch("aptl.core.exporter.boto3", create=True)
    def test_export_s3_tags(self, mock_boto3, tmp_path):
        store = self._make_run(tmp_path)
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        export_s3(store, "test-run", "my-bucket", "runs/", tmp_path / "export")

        archive_call = mock_client.upload_file.call_args_list[0]
        extra_args = archive_call[1].get("ExtraArgs", archive_call[0][3] if len(archive_call[0]) > 3 else {})
        assert "Tagging" in extra_args
        assert "run_id=test-run" in extra_args["Tagging"]

    def test_export_s3_without_boto3(self, tmp_path):
        store = self._make_run(tmp_path)
        import pytest
        import aptl.core.exporter as exporter_mod

        original = exporter_mod.boto3
        exporter_mod.boto3 = None
        try:
            with pytest.raises(ImportError, match="boto3"):
                export_s3(store, "test-run", "bucket", "prefix", tmp_path / "export")
        finally:
            exporter_mod.boto3 = original

    @patch("aptl.core.exporter.boto3", create=True)
    def test_export_s3_creates_local_archive(self, mock_boto3, tmp_path):
        store = self._make_run(tmp_path)
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        output_dir = tmp_path / "export"

        export_s3(store, "test-run", "my-bucket", "runs/", output_dir)

        archive = output_dir / "test-run.tar.gz"
        assert archive.exists()
