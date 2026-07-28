"""CLI tests for ``aptl runs export-bundle`` and ``aptl runs verify-bundle``."""

from __future__ import annotations

import sys
from pathlib import Path

from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))
import _bundle_fixtures as fixtures  # noqa: E402

from aptl.cli.main import app  # noqa: E402

runner = CliRunner()


def _project_with_run(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    run_dir = project / "runs" / "run-1"
    fixtures.build_ready_to_seal_run(run_dir, run_id="run-1", evidence_count=2)
    return project


class TestExportBundleCommand:
    def test_exports_and_reports_unsealed(self, tmp_path: Path) -> None:
        project = _project_with_run(tmp_path)
        out = tmp_path / "exports"
        result = runner.invoke(
            app,
            [
                "runs",
                "export-bundle",
                "run-1",
                "-d",
                str(project),
                "-o",
                str(out),
                "-p",
                "jsonl",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Exported evidence bundle" in result.output
        assert "root identity" in result.output
        assert "UNSEALED" in result.output
        assert (out / "run-1.evidence-bundle.tar").exists()

    def test_unknown_projection_is_rejected(self, tmp_path: Path) -> None:
        project = _project_with_run(tmp_path)
        result = runner.invoke(
            app,
            ["runs", "export-bundle", "run-1", "-d", str(project), "-p", "yaml"],
        )
        assert result.exit_code == 1
        assert "Unknown projection format" in result.output


class TestVerifyBundleCommand:
    def test_verifies_a_freshly_exported_bundle(self, tmp_path: Path) -> None:
        project = _project_with_run(tmp_path)
        out = tmp_path / "exports"
        runner.invoke(
            app, ["runs", "export-bundle", "run-1", "-d", str(project), "-o", str(out)]
        )
        bundle = out / "run-1.evidence-bundle.tar"
        result = runner.invoke(app, ["runs", "verify-bundle", str(bundle)])
        assert result.exit_code == 0, result.output
        assert "OK: bundle verified" in result.output

    def test_reports_failure_on_a_non_bundle(self, tmp_path: Path) -> None:
        bogus = tmp_path / "bogus.tar"
        bogus.write_bytes(b"not a tar archive")
        result = runner.invoke(app, ["runs", "verify-bundle", str(bogus)])
        assert result.exit_code == 1
        assert "FAILED" in result.output
