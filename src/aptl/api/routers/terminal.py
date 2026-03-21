"""WebSocket terminal endpoint for container SSH access."""

import asyncio
import json
from pathlib import Path

import asyncssh
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from aptl.api.deps import get_project_dir
from aptl.core.lab import lab_status
from aptl.core.ssh import _KEY_NAME
from aptl.utils.logging import get_logger

log = get_logger("api.terminal")

router = APIRouter(tags=["terminal"])

# SSH endpoint map: container -> (port, username)
SSH_ENDPOINTS: dict[str, tuple[int, str]] = {
    "victim": (2022, "labadmin"),
    "kali": (2023, "kali"),
    "reverse": (2027, "labadmin"),
    "workstation": (2028, "labadmin"),
}


def _get_key_path() -> Path:
    """Resolve the SSH private key path."""
    return Path.home() / ".ssh" / _KEY_NAME


async def _relay_ssh_to_ws(
    process: asyncssh.SSHClientProcess,
    websocket: WebSocket,
) -> None:
    """Read SSH stdout and forward to WebSocket."""
    try:
        while True:
            data = await process.stdout.read(4096)
            if not data:
                break
            await websocket.send_json({"type": "stdout", "data": data})
    except (asyncio.CancelledError, WebSocketDisconnect):
        pass


async def _relay_ws_to_ssh(
    websocket: WebSocket,
    process: asyncssh.SSHClientProcess,
) -> None:
    """Read WebSocket messages and forward to SSH stdin or handle resize."""
    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type")
            if msg_type == "stdin":
                process.stdin.write(msg.get("data", ""))
            elif msg_type == "resize":
                cols = msg.get("cols", 80)
                rows = msg.get("rows", 24)
                process.change_terminal_size(cols, rows)
    except (asyncio.CancelledError, WebSocketDisconnect, json.JSONDecodeError):
        pass


@router.websocket("/terminal/ws/{container}")
async def terminal_ws(
    websocket: WebSocket,
    container: str,
    project_dir: Path = Depends(get_project_dir),
) -> None:
    """WebSocket endpoint for interactive terminal sessions.

    Opens an SSH PTY connection to the specified container and relays
    stdin/stdout between the WebSocket and the SSH process.
    """
    # Validate container name
    if container not in SSH_ENDPOINTS:
        await websocket.accept()
        await websocket.close(code=1008, reason="Unknown container")
        log.warning("Rejected terminal connection for unknown container")
        return

    # Check lab is running
    status = await asyncio.to_thread(lab_status, project_dir=project_dir)
    if not status.running:
        await websocket.accept()
        await websocket.send_json(
            {"type": "error", "message": "Lab is not running"}
        )
        await websocket.close(code=1008, reason="Lab not running")
        log.warning("Rejected terminal connection: lab not running")
        return

    port, username = SSH_ENDPOINTS[container]
    key_path = _get_key_path()

    await websocket.accept()
    log.info("Terminal WebSocket accepted on port %d", port)

    conn = None
    try:
        conn = await asyncssh.connect(
            host="localhost",
            port=port,
            username=username,
            client_keys=[str(key_path)],
            known_hosts=None,
        )
        process = await conn.create_process(
            term_type="xterm-256color",
            term_size=(80, 24),
        )

        await asyncio.gather(
            _relay_ssh_to_ws(process, websocket),
            _relay_ws_to_ssh(websocket, process),
        )
    except asyncssh.Error as exc:
        log.exception("SSH connection error on port %d", port)
        try:
            await websocket.send_json(
                {"type": "error", "message": f"SSH connection failed: {exc}"}
            )
        except Exception:
            pass
    except WebSocketDisconnect:
        log.info("Terminal WebSocket disconnected from port %d", port)
    finally:
        if conn is not None:
            conn.close()
        log.info("Terminal session cleaned up for port %d", port)
