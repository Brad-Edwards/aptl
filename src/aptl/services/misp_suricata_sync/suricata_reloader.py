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
_DEFAULT_TIMEOUT = 5.0


class SuricataReloader:
    """Speak Suricata's unix-command JSON protocol to trigger rule reload."""

    def __init__(self, socket_path: Path, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._socket_path = socket_path
        self._timeout = timeout

    def reload_rules(self) -> bool:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._timeout)
                sock.connect(str(self._socket_path))

                if not self._send_command(
                    sock, {"version": _PROTOCOL_VERSION}
                ):
                    log.warning(
                        "Suricata rule reload skipped: handshake rejected"
                    )
                    return False

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
