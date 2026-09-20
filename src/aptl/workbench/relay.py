"""Bounded MCP relay; authorization is rechecked throughout each connection."""

from __future__ import annotations

import asyncio
import json
import signal
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from anyio import CancelScope

from aptl.workbench.dispatch import ProtocolAdmission
from aptl.workbench.mcp_results import redact_mcp_result
from aptl.workbench.process import _signal_group
from aptl.workbench.profiles import ServerProfile, WorkbenchConfigurationError

TOOLS_LIST = "tools/list"

_MAX_FRAME = 1024 * 1024
_PRIVATE_ID = "aptl-admission-inventory"


async def _read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
    """Read one bounded JSON-RPC frame from the transport."""
    frame = await reader.readline()
    if not frame or len(frame) > _MAX_FRAME:
        raise WorkbenchConfigurationError(
            "MCP connection closed or frame limit exceeded"
        )
    value = json.loads(frame)
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise WorkbenchConfigurationError("invalid MCP protocol frame")
    return value


async def _write_message(writer: MessageWriter, value: dict[str, Any]) -> None:
    """Write one bounded JSON-RPC frame with a flush deadline."""
    data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    if len(data) > _MAX_FRAME:
        raise WorkbenchConfigurationError("MCP response exceeds frame limit")
    writer.write(data)
    await asyncio.wait_for(writer.drain(), timeout=30)


class MessageWriter(Protocol):
    """Frame output shared by SSH streams and browser websocket adapters."""

    def write(self, data: bytes) -> None:
        """Buffer serialized frame bytes."""
        ...

    async def drain(self) -> None:
        """Flush pending frame bytes."""
        ...


@dataclass(frozen=True)
class RelayLaunch:
    """Guest-owned process inputs, independent of participant protocol data."""

    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    server: ServerProfile


class _Relay:
    """Serialize MCP calls through a continuously authorized child process."""

    def __init__(
        self,
        child: asyncio.subprocess.Process,
        reader: asyncio.StreamReader,
        writer: MessageWriter,
        server: ServerProfile,
        authorize: Callable[[], None],
        check_revocation: Callable[[], None] | None,
    ) -> None:
        self.child = child
        self.reader = reader
        self.writer = writer
        self.gate = ProtocolAdmission(server)
        self.authorize = authorize
        self.check_revocation = check_revocation or authorize
        self.requests = asyncio.Queue(maxsize=8)
        self.ids = set()
        self.output_bytes = 0

    async def receive(self) -> None:
        """Read bounded client frames for the admitted relay."""
        while True:
            request = await asyncio.wait_for(_read_message(self.reader), timeout=300)
            await asyncio.to_thread(self.check_revocation)
            identifier = request.get("id")
            if "id" in request:
                if (
                    isinstance(identifier, bool)
                    or not isinstance(identifier, (str, int))
                    or identifier == _PRIVATE_ID
                    or identifier in self.ids
                ):
                    raise WorkbenchConfigurationError(
                        "invalid or duplicate MCP request ID"
                    )
                self.ids.add(identifier)
            self.gate.request(request)
            if request["method"] == "notifications/cancelled":
                await _write_message(self.child.stdin, request)
            else:
                await asyncio.wait_for(self.requests.put(request), timeout=30)

    async def dispatch(self) -> None:
        """Serialize admitted calls and redact backend data before forwarding."""
        while True:
            request = await self.requests.get()
            check = (
                self.authorize
                if request["method"] == "tools/call"
                else self.check_revocation
            )
            await asyncio.to_thread(check)
            if request["method"] == "notifications/initialized":
                # The private admission handshake already sent this.
                continue
            if request["method"] == "initialize":
                request["params"]["capabilities"] = {}
            await _write_message(self.child.stdin, request)
            if "id" not in request:
                continue
            response = await asyncio.wait_for(
                self._response(request["id"]), timeout=120
            )
            if request["method"] == "initialize":
                await self._admit_backend(response)
            elif request["method"] == TOOLS_LIST:
                self.gate.admit_inventory(response.get("result", {}))
            await asyncio.to_thread(check)
            await self._forward_response(response, request)
            self.ids.discard(request["id"])

    async def _forward_response(
        self, response: dict[str, Any], request: dict[str, Any]
    ) -> None:
        """Redact result data while preserving the admitted protocol schema."""
        # Control-plane redaction remains enabled regardless of capture opt-outs.
        safe = dict(response)
        # tools/list is the admitted interface schema, not captured data.
        # Redacting property names such as session_id corrupts JSON Schema.
        if "result" in safe and request["method"] != TOOLS_LIST:
            safe["result"] = redact_mcp_result(
                safe["result"],
                self.gate.server.server_id,
                request.get("params", {}).get("name", ""),
            )
        if "error" in safe:
            safe["error"] = {"code": -32603, "message": "Guest MCP request failed"}
        self.output_bytes += len(json.dumps(safe).encode())
        if self.output_bytes > 64 * _MAX_FRAME:
            raise WorkbenchConfigurationError("MCP connection output limit exceeded")
        await _write_message(self.writer, safe)

    async def _response(self, identifier: str | int) -> dict[str, Any]:
        """Read the matching response while ignoring bounded notifications."""
        for _ in range(32):
            response = await _read_message(self.child.stdout)
            if response.get("id") == identifier and (
                "result" in response or "error" in response
            ):
                return response
            # Server-initiated capabilities are unsupported. Do not expose server
            # logging/resources/sampling or allow host paths to enter guest state.
            if "id" in response or not str(response.get("method", "")).startswith(
                "notifications/"
            ):
                break
        raise WorkbenchConfigurationError("unexpected MCP backend response")

    async def _admit_backend(self, initialize_response: dict[str, Any]) -> None:
        """Perform the private backend initialization and inventory handshake."""
        if "result" not in initialize_response:
            raise WorkbenchConfigurationError("MCP initialization failed")
        await _write_message(
            self.child.stdin, {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        await _write_message(
            self.child.stdin,
            {"jsonrpc": "2.0", "id": _PRIVATE_ID, "method": TOOLS_LIST, "params": {}},
        )
        inventory = await asyncio.wait_for(self._response(_PRIVATE_ID), timeout=30)
        self.gate.admit_inventory(inventory.get("result", {}))
        initialize_response["result"]["capabilities"] = {"tools": {}}

    async def watch(self, interval: float) -> None:
        """Poll authorization until the connection must close."""
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self.authorize)


async def _stop(child: asyncio.subprocess.Process) -> bool:
    # Common MCP's SIGTERM handler awaits remote SSH teardown and reports a
    # nonzero exit on cleanup failure. A killed or failed child is not proof.
    """Terminate and reap the MCP process and report cleanup success."""
    _signal_group(child.pid, signal.SIGTERM)
    try:
        code = await asyncio.wait_for(child.wait(), timeout=30)
        clean = code == 0
    except asyncio.TimeoutError:
        clean = False
    finally:
        _signal_group(child.pid, signal.SIGKILL)
        await child.wait()
        child.stdin.close()
        try:
            await child.stdin.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass
    return clean


async def relay_mcp(
    reader: asyncio.StreamReader,
    writer: MessageWriter,
    *,
    launch: RelayLaunch,
    authorize: Callable[[], None],
    cleanup_observer: Callable[[bool], None],
    poll_seconds: float = 0.25,
    check_revocation: Callable[[], None] | None = None,
    authorization_poll_seconds: float = 10,
) -> None:
    """Run only trusted guest argv; close and report every connection's cleanup.

    The forced dispatcher, never the SSH request, supplies argv/environment.
    The caller persists failed cleanup as a taint blocking later admission.
    """
    await asyncio.to_thread(authorize)
    child = await asyncio.create_subprocess_exec(
        *launch.argv,
        cwd=launch.cwd,
        env=dict(launch.env),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
        limit=_MAX_FRAME,
    )
    relay = _Relay(
        child, reader, writer, launch.server, authorize, check_revocation
    )
    authorization_interval = (
        authorization_poll_seconds if check_revocation is not None else poll_seconds
    )
    tasks = [
        asyncio.create_task(coro)
        for coro in (
            relay.receive(),
            relay.dispatch(),
            relay.watch(authorization_interval),
            child.wait(),
        )
    ]
    if check_revocation is not None:
        tasks.append(
            asyncio.create_task(_watch_revocation(check_revocation, poll_seconds))
        )
    try:
        await asyncio.wait(tasks, timeout=3600, return_when=asyncio.FIRST_COMPLETED)
    finally:
        # ASGI disconnect cancellation must not interrupt process reaping or
        # leave a captured session alive after the browser has gone away.
        with CancelScope(shield=True):
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            cleanup_observer(await _stop(child))


async def _watch_revocation(check: Callable[[], None], interval: float) -> None:
    """Poll the cheap grant check independently of deployment observations."""
    while True:
        await asyncio.to_thread(check)
        await asyncio.sleep(interval)
