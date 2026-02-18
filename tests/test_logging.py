"""Tests for the structured logging setup.

Tests our logging configuration logic, not the logging module itself.
"""

import json
import logging

import pytest


class TestLoggingSetup:
    """Tests for logging configuration."""

    def test_setup_creates_aptl_logger(self):
        """setup_logging should configure the 'aptl' logger."""
        from aptl.utils.logging import setup_logging

        setup_logging()
        logger = logging.getLogger("aptl")
        assert logger.level <= logging.DEBUG
        assert len(logger.handlers) > 0

    def test_setup_respects_level_parameter(self):
        """setup_logging(level=WARNING) should set logger to WARNING."""
        from aptl.utils.logging import setup_logging

        setup_logging(level=logging.WARNING)
        logger = logging.getLogger("aptl")
        assert logger.level == logging.WARNING

    def test_get_logger_returns_child_logger(self):
        """get_logger('config') should return aptl.config logger."""
        from aptl.utils.logging import get_logger

        logger = get_logger("config")
        assert logger.name == "aptl.config"

    def test_setup_does_not_duplicate_handlers(self):
        """Calling setup_logging twice should not add duplicate handlers."""
        from aptl.utils.logging import setup_logging

        setup_logging()
        handler_count_1 = len(logging.getLogger("aptl").handlers)
        setup_logging()
        handler_count_2 = len(logging.getLogger("aptl").handlers)
        assert handler_count_2 == handler_count_1


class TestEcsJsonFormatter:
    """Tests for the ECS JSON log formatter."""

    def _make_record(
        self,
        message: str,
        level: int = logging.INFO,
        name: str = "aptl.test",
        exc_info=None,
    ) -> logging.LogRecord:
        record = logging.LogRecord(
            name=name,
            level=level,
            pathname="",
            lineno=0,
            msg=message,
            args=(),
            exc_info=exc_info,
        )
        return record

    def test_output_is_valid_json(self):
        """EcsJsonFormatter should produce valid JSON."""
        from aptl.utils.logging import EcsJsonFormatter

        fmt = EcsJsonFormatter()
        record = self._make_record("hello")
        output = fmt.format(record)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_required_ecs_fields_present(self):
        """ECS-required fields must be present in every record."""
        from aptl.utils.logging import EcsJsonFormatter

        fmt = EcsJsonFormatter()
        record = self._make_record("test message", level=logging.WARNING)
        data = json.loads(fmt.format(record))

        assert "@timestamp" in data
        assert data["log.level"] == "WARNING"
        assert data["log.logger"] == "aptl.test"
        assert data["message"] == "test message"
        assert data["service.name"] == "aptl"
        assert "ecs.version" in data

    def test_timestamp_is_iso8601_utc(self):
        """@timestamp should be an ISO 8601 UTC string."""
        from aptl.utils.logging import EcsJsonFormatter

        fmt = EcsJsonFormatter()
        record = self._make_record("ts test")
        data = json.loads(fmt.format(record))

        ts = data["@timestamp"]
        assert ts.endswith("+00:00") or ts.endswith("Z"), (
            f"@timestamp should be UTC: {ts}"
        )

    def test_exc_info_populates_error_fields(self):
        """Records with exc_info should include error.* ECS fields."""
        from aptl.utils.logging import EcsJsonFormatter

        fmt = EcsJsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = self._make_record("error occurred", level=logging.ERROR, exc_info=exc_info)
        data = json.loads(fmt.format(record))

        assert data["error.type"] == "ValueError"
        assert data["error.message"] == "boom"
        assert "ValueError" in data["error.stack_trace"]

    def test_no_exc_info_omits_error_fields(self):
        """Records without exc_info should not include error.* fields."""
        from aptl.utils.logging import EcsJsonFormatter

        fmt = EcsJsonFormatter()
        record = self._make_record("normal")
        data = json.loads(fmt.format(record))

        assert "error.type" not in data
        assert "error.message" not in data
        assert "error.stack_trace" not in data

    def test_setup_logging_json_logs_parameter(self):
        """setup_logging(json_logs=True) should attach an EcsJsonFormatter."""
        from aptl.utils.logging import EcsJsonFormatter, setup_logging

        # Reset the aptl logger for this test
        logger = logging.getLogger("aptl")
        logger.handlers.clear()

        setup_logging(json_logs=True)
        assert any(
            isinstance(h.formatter, EcsJsonFormatter)
            for h in logger.handlers
        )

        # Reset back to text for subsequent tests
        logger.handlers.clear()
        setup_logging()

    def test_setup_logging_env_var_selects_json(self, monkeypatch):
        """APTL_LOG_FORMAT=json env var should select the JSON formatter."""
        from aptl.utils.logging import EcsJsonFormatter, setup_logging

        monkeypatch.setenv("APTL_LOG_FORMAT", "json")

        logger = logging.getLogger("aptl")
        logger.handlers.clear()

        setup_logging()
        assert any(
            isinstance(h.formatter, EcsJsonFormatter)
            for h in logger.handlers
        )

        # Clean up
        logger.handlers.clear()
        setup_logging()
