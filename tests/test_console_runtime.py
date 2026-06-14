"""Tests for the console runtime orchestration."""

import asyncio

import pytest

pytest.importorskip("pydantic")

from aptl.console.models import Scratchpad, Session  # noqa: E402
from aptl.console.providers import EchoProvider  # noqa: E402
from aptl.console.registry import McpRegistry  # noqa: E402
from aptl.console.runtime import ConsoleRuntime  # noqa: E402
from aptl.console.store import ConsoleStore  # noqa: E402


@pytest.fixture
def runtime(tmp_path):
    store = ConsoleStore(tmp_path / "state.json")
    return ConsoleRuntime(
        tmp_path,
        store=store,
        registry=McpRegistry([]),
        provider=EchoProvider(),
    )


def _collect(coro_gen):
    async def _run():
        return [event async for event in coro_gen]

    return asyncio.run(_run())


class TestRunTurn:
    def test_persists_user_and_assistant(self, runtime):
        sess = runtime.store.add_session(Session(role="red"))
        events = _collect(runtime.run_turn(sess.id, "hello"))

        types = [e["type"] for e in events]
        assert types[0] == "user_message"
        assert "assistant_message" in types
        assert types[-1] == "end"

        stored = runtime.store.get_session(sess.id)
        assert [m.role for m in stored.messages] == ["user", "assistant"]
        assert stored.messages[0].content == "hello"

    def test_scratchpad_tool_available_when_attached(self, runtime):
        pad = runtime.store.add_scratchpad(Scratchpad(name="findings"))
        sess = runtime.store.add_session(Session(role="red", scratchpads=[pad.id]))

        events = _collect(
            runtime.run_turn(sess.id, '/run scratchpad_write {"name": "findings", "content": "x"}')
        )
        assert any(e["type"] == "tool_result" for e in events)
        assert runtime.store.get_scratchpad(pad.id).content == "x"

    def test_state_includes_provider_status(self, runtime):
        state = runtime.state()
        assert state.provider.provider == "echo"
        assert state.provider.live is False

    def test_default_servers_for_role_empty_registry(self, runtime):
        assert runtime.default_servers_for(Session().role) == []
