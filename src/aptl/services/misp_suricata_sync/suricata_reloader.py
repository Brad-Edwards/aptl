"""Trigger a Suricata rule reload via its unix-command socket.

Implements the minimal slice of Suricata's unix-command protocol we need
(version handshake + ``reload-rules``) without depending on the suricata
package's ``suricatasc`` script.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

from aptl.utils.logging import get_logger

log = get_logger("misp_suricata_sync")

_PROTOCOL_VERSION = "0.2"
_RECV_BUFFER = 4096
# Connect + version handshake are fast (the server replies immediately).
_HANDSHAKE_TIMEOUT = 5.0
# ``reload-rules`` is synchronous on the Suricata side: the response only
# comes back once the new ruleset has been loaded. Empirically the
# baseline lab + ET Open + local + misp rules reload in ~10s on a cold
# engine, so the per-command timeout is sized well above that to absorb
# growth in the rule set without flapping. A permanently-stuck Suricata
# would still block the loop for at most this long per tick.
_RELOAD_TIMEOUT = 60.0


class SuricataReloader:
    """Speak Suricata's unix-command JSON protocol to trigger rule reload."""

    def __init__(
        self,
        socket_path: Path,
        handshake_timeout: float = _HANDSHAKE_TIMEOUT,
        reload_timeout: float = _RELOAD_TIMEOUT,
    ) -> None:
        self._socket_path = socket_path
        self._handshake_timeout = handshake_timeout
        self._reload_timeout = reload_timeout

    def reload_rules(self) -> bool:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._handshake_timeout)
                sock.connect(str(self._socket_path))

                if not self._send_command(
                    sock, {"version": _PROTOCOL_VERSION}
                ):
                    log.warning(
                        "Suricata rule reload skipped: handshake rejected"
                    )
                    return False

                # Reload is synchronous; widen the deadline before issuing.
                sock.settimeout(self._reload_timeout)
                if not self._send_command(sock, {"command": "reload-rules"}):
                    log.warning("Suricata rule reload command failed")
                    return False

                log.info("Suricata rule reload acknowledged")
                return True
        except OSError as exc:
            log.warning(
                "Suricata rule reload skipped: %s",
                exc.__class__.__name__,
            )
            return False

    def _send_command(self, sock: socket.socket, payload: dict) -> bool:
        sock.sendall(json.dumps(payload).encode() + b"\n")
        response = self._recv_line(sock)
        if response is None:
            return False
        return response.get("return") == "OK"

    def _recv_line(self, sock: socket.socket) -> dict | None:
        buf = bytearray()
        while True:
            chunk = sock.recv(_RECV_BUFFER)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\n" in chunk:
                break
        if not buf:
            return None
        try:
            line = buf.split(b"\n", 1)[0]
            return json.loads(line.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
