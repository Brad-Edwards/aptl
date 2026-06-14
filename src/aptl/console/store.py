"""Persistent store for console sessions and scratchpads.

State lives in ``<project>/.aptl/console/state.json`` (the ``.aptl`` tree is
already git-ignored). The store is the single source of truth for sessions
and scratchpads; writes are serialised under a lock and flushed atomically
so a crash mid-write cannot corrupt the file.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Optional

from aptl.console.models import (
    ChatMessage,
    Scratchpad,
    Session,
)
from aptl.utils.logging import get_logger

log = get_logger("console.store")


class ConsoleError(Exception):
    """A console operation the caller got wrong (maps to HTTP 4xx)."""


class NotFoundError(ConsoleError):
    """A referenced session or scratchpad does not exist."""


class ConsoleStore:
    """Thread-safe, file-backed store of sessions and scratchpads."""

    def __init__(self, state_path: Path) -> None:
        self._path = state_path
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}
        self._scratchpads: dict[str, Scratchpad] = {}
        self._load()

    @classmethod
    def for_project(cls, project_dir: Path) -> "ConsoleStore":
        return cls(project_dir / ".aptl" / "console" / "state.json")

    # ---- persistence ----------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Could not read console state %s: %s", self._path, exc)
            return
        for entry in raw.get("sessions", []):
            try:
                sess = Session.model_validate(entry)
                self._sessions[sess.id] = sess
            except Exception as exc:  # noqa: BLE001 — skip individual bad records
                log.warning("Skipping malformed session record: %s", exc)
        for entry in raw.get("scratchpads", []):
            try:
                pad = Scratchpad.model_validate(entry)
                self._scratchpads[pad.id] = pad
            except Exception as exc:  # noqa: BLE001
                log.warning("Skipping malformed scratchpad record: %s", exc)
        log.info(
            "Loaded %d sessions, %d scratchpads from %s",
            len(self._sessions),
            len(self._scratchpads),
            self._path,
        )

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "sessions": [s.model_dump() for s in self._sessions.values()],
            "scratchpads": [p.model_dump() for p in self._scratchpads.values()],
        }
        data = json.dumps(payload, indent=2)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(data)
            os.replace(tmp, self._path)
        except OSError:
            Path(tmp).unlink(missing_ok=True)
            raise

    # ---- sessions -------------------------------------------------------

    def list_sessions(self) -> list[Session]:
        with self._lock:
            return sorted(
                (s.model_copy(deep=True) for s in self._sessions.values()),
                key=lambda s: s.created_at,
            )

    def get_session(self, session_id: str) -> Session:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None:
                raise NotFoundError(f"No such session: {session_id}")
            return sess.model_copy(deep=True)

    def add_session(self, session: Session) -> Session:
        with self._lock:
            self._sessions[session.id] = session
            self._flush()
            return session.model_copy(deep=True)

    def update_session(self, session: Session) -> Session:
        with self._lock:
            if session.id not in self._sessions:
                raise NotFoundError(f"No such session: {session.id}")
            session.touch()
            self._sessions[session.id] = session
            self._flush()
            return session.model_copy(deep=True)

    def delete_session(self, session_id: str) -> None:
        with self._lock:
            if session_id not in self._sessions:
                raise NotFoundError(f"No such session: {session_id}")
            del self._sessions[session_id]
            self._flush()

    def append_message(self, session_id: str, message: ChatMessage) -> ChatMessage:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None:
                raise NotFoundError(f"No such session: {session_id}")
            sess.messages.append(message)
            sess.touch()
            self._flush()
            return message.model_copy(deep=True)

    # ---- scratchpads ----------------------------------------------------

    def list_scratchpads(self) -> list[Scratchpad]:
        with self._lock:
            return sorted(
                (p.model_copy(deep=True) for p in self._scratchpads.values()),
                key=lambda p: p.created_at,
            )

    def get_scratchpad(self, pad_id: str) -> Scratchpad:
        with self._lock:
            pad = self._scratchpads.get(pad_id)
            if pad is None:
                raise NotFoundError(f"No such scratchpad: {pad_id}")
            return pad.model_copy(deep=True)

    def find_scratchpad_by_name(self, name: str) -> Optional[Scratchpad]:
        with self._lock:
            for pad in self._scratchpads.values():
                if pad.name == name:
                    return pad.model_copy(deep=True)
            return None

    def add_scratchpad(self, pad: Scratchpad) -> Scratchpad:
        with self._lock:
            self._scratchpads[pad.id] = pad
            self._flush()
            return pad.model_copy(deep=True)

    def update_scratchpad(self, pad: Scratchpad) -> Scratchpad:
        import time

        with self._lock:
            if pad.id not in self._scratchpads:
                raise NotFoundError(f"No such scratchpad: {pad.id}")
            pad.updated_at = time.time()
            self._scratchpads[pad.id] = pad
            self._flush()
            return pad.model_copy(deep=True)

    def delete_scratchpad(self, pad_id: str) -> None:
        with self._lock:
            if pad_id not in self._scratchpads:
                raise NotFoundError(f"No such scratchpad: {pad_id}")
            del self._scratchpads[pad_id]
            # Detach from any sessions referencing it so no dangling ids remain.
            for sess in self._sessions.values():
                if pad_id in sess.scratchpads:
                    sess.scratchpads = [p for p in sess.scratchpads if p != pad_id]
            self._flush()
