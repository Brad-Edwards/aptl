"""Tests for the RAES diagnostics rendering helper (ADR-047 error envelope).

``render_raes_diagnostics()`` previously hard-coded the "RAES runtime
handoff failed" stage label. ADR-047 reuses this formatter for the future
experiment-admission failure surface by parameterizing that label instead
of adding a second formatter — every existing caller keeps the exact
original default text.
"""

from raes_contracts.diagnostics import Diagnostic, Severity

from aptl.backends.raes_diagnostics import render_raes_diagnostics


def _diagnostic(message: str, *, severity: Severity = Severity.ERROR) -> Diagnostic:
    return Diagnostic(
        code="test.diagnostic",
        domain="provisioning",
        address="test.address",
        message=message,
        severity=severity,
    )


class TestDefaultStageLabelIsUnchanged:
    def test_empty_diagnostics(self):
        assert render_raes_diagnostics([]) == "RAES runtime handoff failed."

    def test_with_error_diagnostics(self):
        rendered = render_raes_diagnostics([_diagnostic("boom")])
        assert rendered.startswith("RAES runtime handoff failed: ")
        assert "boom" in rendered

    def test_with_only_non_error_diagnostics(self):
        rendered = render_raes_diagnostics([_diagnostic("heads up", severity=Severity.WARNING)])
        assert rendered.startswith("RAES runtime handoff failed: ")
        assert "heads up" in rendered


class TestCustomStageLabel:
    def test_empty_diagnostics_uses_custom_label(self):
        rendered = render_raes_diagnostics([], stage_label="RAES experiment admission failed")
        assert rendered == "RAES experiment admission failed."

    def test_with_diagnostics_uses_custom_label_prefix(self):
        rendered = render_raes_diagnostics(
            [_diagnostic("bad reference")],
            stage_label="RAES experiment admission failed",
        )
        assert rendered.startswith("RAES experiment admission failed: ")
        assert "bad reference" in rendered
        assert "RAES runtime handoff failed" not in rendered

    def test_custom_label_is_still_redacted(self):
        rendered = render_raes_diagnostics(
            [_diagnostic("Authorization: Bearer abc.def.ghi")],
            stage_label="RAES experiment admission failed",
        )
        assert "abc.def.ghi" not in rendered
        assert "[REDACTED]" in rendered
