"""Authorized MCP session handles remain usable without exposing credentials."""

import json

from aptl.workbench.mcp_results import redact_mcp_result


def result(value):
    return {"content": [{"type": "text", "text": json.dumps(value)}]}


def payload(value):
    return json.loads(value["content"][0]["text"])


def test_session_handle_round_trips_but_credentials_and_output_are_redacted():
    source = result(
        {
            "session_id": "session_123",
            "session_mode": "normal",
            "password": "private",
            "output": "password=private",
        }
    )
    safe = payload(redact_mcp_result(source, "aptl-red", "kali_session_command"))
    assert safe["session_id"] == "session_123"
    assert safe["session_mode"] == "normal"
    assert safe["password"] == "[REDACTED]"
    assert "private" not in safe["output"]
    assert payload(source)["password"] == "private"


def test_session_listing_retains_only_valid_handles_in_sanitized_rows():
    source = result(
        {
            "sessions": [{"session_id": "session_123", "password": "private"}],
            "total_sessions": 1,
            "token": "private",
        }
    )
    safe = payload(redact_mcp_result(source, "aptl-red", "kali_list_sessions"))
    assert safe["sessions"] == [{"session_id": "session_123", "password": "[REDACTED]"}]
    assert safe["total_sessions"] == 1
    assert safe["token"] == "[REDACTED]"


def test_api_sessions_and_invalid_terminal_handles_stay_redacted():
    source = result({"session_id": "session_123"})
    assert (
        payload(redact_mcp_result(source, "aptl-indexer", "indexer_query"))[
            "session_id"
        ]
        == "[REDACTED]"
    )
    for value in ("../private", "x" * 129, "password=private", {"password": "private"}):
        safe = payload(
            redact_mcp_result(
                result({"session_id": value}), "aptl-red", "kali_session_command"
            )
        )
        assert safe["session_id"] == "[REDACTED]"
