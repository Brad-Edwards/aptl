"""Tests for the structured logging setup.

Tests our logging configuration logic, not the logging module itself.
"""

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
