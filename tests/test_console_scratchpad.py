"""Tests for the shared-scratchpad tool layer."""

import asyncio

import pytest

pytest.importorskip("pydantic")

from aptl.console.models import Scratchpad, Session  # noqa: E402
from aptl.console.store import ConsoleStore  # noqa: E402
from aptl.console.tools import build_scratchpad_tools  # noqa: E402


@pytest.fixture
def store(tmp_path):
    return ConsoleStore(tmp_path / "state.json")


def _tool(tools, name):
    return next(t for t in tools if t.name == name)


def _run(coro):
    return asyncio.run(coro)


class TestScratchpadTools:
    def test_no_tools_without_attachments(self, store):
        assert build_scratchpad_tools(store, []) == []

    def test_write_then_read(self, store):
        pad = store.add_scratchpad(Scratchpad(name="findings"))
        tools = build_scratchpad_tools(store, [pad.id])
        _run(_tool(tools, "scratchpad_write").handler({"name": "findings", "content": "creds found"}))
        out = _run(_tool(tools, "scratchpad_read").handler({"name": "findings"}))
        assert out == "creds found"
        assert store.get_scratchpad(pad.id).content == "creds found"

    def test_append_mode(self, store):
        pad = store.add_scratchpad(Scratchpad(name="log", content="line1"))
        tools = build_scratchpad_tools(store, [pad.id])
        _run(
            _tool(tools, "scratchpad_write").handler(
                {"name": "log", "content": "line2", "mode": "append"}
            )
        )
        assert store.get_scratchpad(pad.id).content == "line1\nline2"

    def test_cross_session_handoff(self, store):
        """A pad written by one session's tools is visible to another's."""
        pad = store.add_scratchpad(Scratchpad(name="shared"))
        store.add_session(Session(role="red", scratchpads=[pad.id]))
        store.add_session(Session(role="blue", scratchpads=[pad.id]))

        red_tools = build_scratchpad_tools(store, [pad.id])
        blue_tools = build_scratchpad_tools(store, [pad.id])

        _run(_tool(red_tools, "scratchpad_write").handler({"name": "shared", "content": "red says hi"}))
        out = _run(_tool(blue_tools, "scratchpad_read").handler({"name": "shared"}))
        assert out == "red says hi"

    def test_read_unknown_name(self, store):
        pad = store.add_scratchpad(Scratchpad(name="a"))
        tools = build_scratchpad_tools(store, [pad.id])
        out = _run(_tool(tools, "scratchpad_read").handler({"name": "ghost"}))
        assert "No attached scratchpad" in out

    def test_list(self, store):
        p1 = store.add_scratchpad(Scratchpad(name="alpha", content="first line\nmore"))
        p2 = store.add_scratchpad(Scratchpad(name="beta"))
        tools = build_scratchpad_tools(store, [p1.id, p2.id])
        out = _run(_tool(tools, "scratchpad_list").handler({}))
        assert "alpha" in out and "beta" in out
