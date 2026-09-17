"""Participant browser terminal over the same admitted guest MCP relay."""

from __future__ import annotations

import asyncio
import html
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from aptl.workbench.app import BrowserPrincipal
from aptl.workbench.dispatch import DispatchSelector
from aptl.workbench.guest_binding import GuestAdmission, read_private_binding
from aptl.workbench.relay import relay_mcp

_TERMINAL = """<!doctype html><html lang="en"><meta charset="utf-8"><title>Kali terminal</title>
<h1>Kali terminal</h1><p>Commands run in this seat's captured Kali session.</p>
<label for="command">Command</label><input id="command" maxlength="16000"><button id="send" disabled>Run</button>
<pre id="output" aria-live="polite"></pre><script>
const output=document.querySelector('#output'),button=document.querySelector('#send');
const ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+'/workbench/mcp/aptl-red');
let id=0;
function call(method,params){ws.send(JSON.stringify({jsonrpc:'2.0',id:++id,method,params}));}
ws.onopen=()=>call('initialize',{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'aptl-browser',version:'1'}});
ws.onmessage=event=>{const response=JSON.parse(event.data);if(response.id===1){button.disabled=false;return;}
 output.textContent+=JSON.stringify(response.result||response.error,null,2)+'\\n';button.disabled=false;};
ws.onclose=()=>{button.disabled=true;output.textContent+='\\nSession closed. Reload after access is restored.';};
button.onclick=()=>{button.disabled=true;call('tools/call',{name:'kali_run_command',arguments:{command:document.querySelector('#command').value}});};
</script></html>"""


class _SocketWriter:
    def __init__(self, socket):
        self.socket = socket
        self.pending = b""

    def write(self, data):
        self.pending += data

    async def drain(self):
        data, self.pending = self.pending, b""
        await self.socket.send_text(data.decode().rstrip("\n"))


def attach_browser_mcp(
    app, *, binding_path: Path, grant_id: str, authorizer, guide: str
):
    """Attach participant-only guide and terminal routes; no operator API mount."""

    def principal(request):
        value = authorizer(request)
        if not isinstance(value, BrowserPrincipal) or value.caller_id != grant_id:
            raise HTTPException(401, "Participant session required")
        return value

    @app.get("/guide/", response_class=HTMLResponse)
    def guide_page(request: Request):
        principal(request)
        return HTMLResponse(
            "<!doctype html><title>TechVault guide</title><pre>"
            + html.escape(guide)
            + "</pre>",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/desktop/kali/", response_class=HTMLResponse)
    def terminal_page(request: Request):
        if "red" not in principal(request).profiles:
            raise HTTPException(403, "Red role required")
        import base64
        import hashlib

        script = _TERMINAL.split("<script>", 1)[1].split("</script>", 1)[0]
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        return HTMLResponse(
            _TERMINAL,
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": f"default-src 'self'; script-src 'sha256-{digest}'; connect-src 'self'; object-src 'none'; base-uri 'none'",
            },
        )

    @app.websocket("/workbench/mcp/{server_id}")
    async def mcp_socket(socket: WebSocket, server_id: str):
        await _serve_browser_mcp(socket, server_id, binding_path, grant_id, principal)


async def _serve_browser_mcp(socket, server_id, binding_path, grant_id, principal):
    request = Request({**socket.scope, "type": "http"})
    origin = socket.headers.get("origin")
    if origin is not None and urlsplit(origin).netloc != socket.headers.get("host"):
        return await socket.close(code=1008)
    try:
        caller = principal(request)
        binding = read_private_binding(binding_path)
        grant = next(grant for grant in binding.grants if grant.grant_id == grant_id)
        if grant.profile not in caller.profiles:
            raise ValueError("caller role changed")
        selector = DispatchSelector(
            binding.access.instance_id, binding.access.generation, server_id
        )
        with GuestAdmission(
            binding_path, grant_id, grant.public_key_fingerprint, selector
        ) as admission:
            argv, cwd, env = await asyncio.to_thread(admission.launch)

            def authorize():
                current = principal(request)
                if current != caller:
                    raise ValueError("browser caller changed")
                admission.authorize()

            await socket.accept()
            reader = asyncio.StreamReader(limit=1024**2)

            async def receive():
                try:
                    while True:
                        frame = await socket.receive_text()
                        if (
                            len(frame.encode()) > 1024**2
                            or len(reader._buffer) > 8 * 1024**2
                        ):
                            break
                        reader.feed_data(frame.encode() + b"\n")
                finally:
                    reader.feed_eof()

            receiver = asyncio.create_task(receive())
            try:
                await relay_mcp(
                    reader,
                    _SocketWriter(socket),
                    argv=argv,
                    cwd=cwd,
                    env=env,
                    server=admission.server,
                    authorize=authorize,
                    cleanup_observer=admission.cleanup,
                    check_revocation=admission.check_revocation,
                )
            finally:
                receiver.cancel()
                await asyncio.gather(receiver, return_exceptions=True)
    except (ValueError, OSError, HTTPException, StopIteration, WebSocketDisconnect):
        pass
    finally:
        try:
            await socket.close(code=1000)
        except RuntimeError:
            pass
