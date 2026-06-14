"""Tests for the console agent providers (offline echo provider + selection)."""

import asyncio
import os
from unittest.mock import patch

import pytest

pytest.importorskip("pydantic")

from aptl.console.models import ChatMessage, Scratchpad  # noqa: E402
from aptl.console.providers import (  # noqa: E402
    EchoProvider,
    select_provider,
)
from aptl.console.store import ConsoleStore  # noqa: E402
from aptl.console.tools import build_scratchpad_tools  # noqa: E402


def _collect(coro_gen):
    async def _run():
        return [event async for event in coro_gen]

    return asyncio.run(_run())


def _history(text):
    return [ChatMessage(role="user", content=text)]


class TestEchoProvider:
    def test_guided_reply_lists_tools(self):
        provider = EchoProvider()
        events = _collect(
            provider.run_turn(system="s", history=_history("hello"), tools=[])
        )
        assert any(e["type"] == "token" for e in events)
        done = [e for e in events if e["type"] == "done"]
        assert len(done) == 1
        assert "Demo mode" in done[0]["text"]

    def test_help_command(self):
        provider = EchoProvider()
        events = _collect(
            provider.run_turn(system="s", history=_history("/help"), tools=[])
        )
        done = [e for e in events if e["type"] == "done"][0]
        assert "/run" in done["text"]

    def test_run_executes_real_tool(self, tmp_path):
        store = ConsoleStore(tmp_path / "state.json")
        pad = store.add_scratchpad(Scratchpad(name="notes"))
        tools = build_scratchpad_tools(store, [pad.id])
        provider = EchoProvider()

        events = _collect(
            provider.run_turn(
                system="s",
                history=_history('/run scratchpad_write {"name": "notes", "content": "hi"}'),
                tools=tools,
            )
        )
        kinds = [e["type"] for e in events]
        assert "tool_call" in kinds
        assert "tool_result" in kinds
        # The tool actually ran against the store.
        assert store.get_scratchpad(pad.id).content == "hi"
        done = [e for e in events if e["type"] == "done"][0]
        assert len(done["tool_calls"]) == 1

    def test_run_unknown_tool(self):
        provider = EchoProvider()
        events = _collect(
            provider.run_turn(system="s", history=_history("/run nope {}"), tools=[])
        )
        done = [e for e in events if e["type"] == "done"][0]
        assert "No tool named" in done["text"]

    def test_run_bad_json(self, tmp_path):
        store = ConsoleStore(tmp_path / "state.json")
        pad = store.add_scratchpad(Scratchpad(name="notes"))
        tools = build_scratchpad_tools(store, [pad.id])
        provider = EchoProvider()
        events = _collect(
            provider.run_turn(
                system="s",
                history=_history("/run scratchpad_list not-json"),
                tools=tools,
            )
        )
        done = [e for e in events if e["type"] == "done"][0]
        assert "Could not parse" in done["text"]


class TestSelectProvider:
    def test_no_key_yields_echo(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            assert select_provider().name == "echo"

    def test_key_yields_anthropic_when_installed(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            provider = select_provider()
            # anthropic is installed in this env via the [console] extra.
            assert provider.name == "anthropic"
            status = provider.status()
            assert status.live is True
