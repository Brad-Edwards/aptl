"""Structured logging setup for APTL CLI."""

import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_ECS_VERSION = "8.11.0"
_SERVICE_NAME = "aptl"


class EcsJsonFormatter(logging.Formatter):
    """JSON log formatter following the Elastic Common Schema (ECS).

    Emits one JSON object per log record with ECS fields:
    - ``@timestamp``: ISO 8601 UTC timestamp with millisecond precision.
    - ``log.level``: Uppercase log level (e.g. "INFO", "ERROR").
    - ``log.logger``: Logger name (e.g. "aptl.lab").
    - ``message``: The formatted log message.
    - ``service.name``: Fixed to "aptl".
    - ``ecs.version``: ECS specification version.

    When ``exc_info`` is present the record also includes:
    - ``error.type``: Exception class name.
    - ``error.message``: Exception string representation.
    - ``error.stack_trace``: Full formatted traceback.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Serialize *record* to an ECS-compliant JSON string."""
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
            timespec="milliseconds"
        )
        doc: dict = {
            "@timestamp": ts,
            "log.level": record.levelname,
            "log.logger": record.name,
            "message": record.getMessage(),
            "service.name": _SERVICE_NAME,
            "ecs.version": _ECS_VERSION,
        }
        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            doc["error.type"] = exc_type.__name__ if exc_type else ""
            doc["error.message"] = str(exc_value) if exc_value else ""
            doc["error.stack_trace"] = "".join(
                traceback.format_exception(exc_type, exc_value, exc_tb)
            ).rstrip()
        return json.dumps(doc, ensure_ascii=False)


def setup_logging(level: int = logging.DEBUG, *, json_logs: bool = False) -> None:
    """Configure the aptl root logger.

    Idempotent: calling multiple times will not add duplicate handlers.

    Args:
        level: Logging level for the aptl logger.
        json_logs: Emit ECS-compliant JSON records instead of plain text.
            Can also be enabled by setting the environment variable
            ``APTL_LOG_FORMAT=json``.
    """
    use_json = json_logs or os.environ.get("APTL_LOG_FORMAT", "").lower() == "json"

    logger = logging.getLogger("aptl")
    logger.setLevel(level)

    # Avoid adding duplicate handlers on repeated calls
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)
        formatter: logging.Formatter = (
            EcsJsonFormatter()
            if use_json
            else logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        # Update existing handler levels
        logger.setLevel(level)
        for handler in logger.handlers:
            handler.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the aptl namespace.

    Args:
        name: Module name (e.g., 'config', 'lab').

    Returns:
        A logger named 'aptl.<name>'.
    """
    return logging.getLogger(f"aptl.{name}")
