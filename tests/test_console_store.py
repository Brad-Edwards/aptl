"""Tests for the console persistence store."""

import pytest

pytest.importorskip("pydantic")

from aptl.console.models import ChatMessage, Scratchpad, Session  # noqa: E402
from aptl.console.store import ConsoleStore, NotFoundError  # noqa: E402


@pytest.fixture
def store(tmp_path):
    return ConsoleStore(tmp_path / ".aptl" / "console" / "state.json")


class TestSessions:
    def test_add_and_get_session(self, store):
        sess = store.add_session(Session(title="red one", role="red"))
        fetched = store.get_session(sess.id)
        assert fetched.title == "red one"
        assert fetched.role.value == "red"

    def test_get_missing_session_raises(self, store):
        with pytest.raises(NotFoundError):
            store.get_session("sess_nope")

    def test_update_session(self, store):
        sess = store.add_session(Session(title="orig"))
        sess.title = "renamed"
        updated = store.update_session(sess)
        assert updated.title == "renamed"
        assert store.get_session(sess.id).title == "renamed"

    def test_delete_session(self, store):
        sess = store.add_session(Session())
        store.delete_session(sess.id)
        with pytest.raises(NotFoundError):
            store.get_session(sess.id)

    def test_sessions_do_not_share_messages(self, store):
        """Red/blue separation: appending to one session never leaks to another."""
        red = store.add_session(Session(role="red"))
        blue = store.add_session(Session(role="blue"))
        store.append_message(red.id, ChatMessage(role="user", content="recon done"))
        assert len(store.get_session(red.id).messages) == 1
        assert len(store.get_session(blue.id).messages) == 0

    def test_list_sessions_sorted_by_creation(self, store):
        a = store.add_session(Session(title="a"))
        b = store.add_session(Session(title="b"))
        ids = [s.id for s in store.list_sessions()]
        assert ids == [a.id, b.id]


class TestScratchpads:
    def test_add_and_get(self, store):
        pad = store.add_scratchpad(Scratchpad(name="findings", content="x"))
        assert store.get_scratchpad(pad.id).content == "x"

    def test_find_by_name(self, store):
        store.add_scratchpad(Scratchpad(name="shared"))
        assert store.find_scratchpad_by_name("shared") is not None
        assert store.find_scratchpad_by_name("missing") is None

    def test_update_bumps_timestamp(self, store):
        pad = store.add_scratchpad(Scratchpad(name="p", content="a"))
        original = pad.updated_at
        pad.content = "b"
        updated = store.update_scratchpad(pad)
        assert updated.content == "b"
        assert updated.updated_at >= original

    def test_delete_detaches_from_sessions(self, store):
        pad = store.add_scratchpad(Scratchpad(name="p"))
        sess = store.add_session(Session(scratchpads=[pad.id]))
        store.delete_scratchpad(pad.id)
        assert store.get_session(sess.id).scratchpads == []


class TestPersistence:
    def test_state_survives_reload(self, tmp_path):
        path = tmp_path / ".aptl" / "console" / "state.json"
        store = ConsoleStore(path)
        sess = store.add_session(Session(title="persisted", role="blue"))
        store.add_scratchpad(Scratchpad(name="memo", content="hi"))

        reloaded = ConsoleStore(path)
        assert reloaded.get_session(sess.id).title == "persisted"
        assert reloaded.find_scratchpad_by_name("memo").content == "hi"

    def test_corrupt_file_is_tolerated(self, tmp_path):
        path = tmp_path / ".aptl" / "console" / "state.json"
        path.parent.mkdir(parents=True)
        path.write_text("{ not json")
        store = ConsoleStore(path)
        assert store.list_sessions() == []
